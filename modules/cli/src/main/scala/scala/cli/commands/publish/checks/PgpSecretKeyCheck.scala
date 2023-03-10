package scala.cli.commands.publish.checks

import coursier.cache.{ArchiveCache, FileCache}
import coursier.util.Task
import sttp.client3._
import sttp.model.Uri

import java.util.Base64

import scala.build.EitherCps.{either, value}
import scala.build.Logger
import scala.build.Ops._
import scala.build.errors.{BuildException, CompositeBuildException, MalformedCliInputError}
import scala.build.options.{PublishOptions => BPublishOptions}
import scala.cli.commands.config.ThrowawayPgpSecret
import scala.cli.commands.pgp.{KeyServer, PgpProxyMaker}
import scala.cli.commands.publish.ConfigUtil._
import scala.cli.commands.publish.{OptionCheck, PublishSetupOptions, SetSecret}
import scala.cli.commands.util.JvmUtils
import scala.cli.config.{ConfigDb, Keys, PasswordOption}
import scala.cli.errors.MissingPublishOptionError
import scala.cli.util.ConfigPasswordOptionHelpers._
import scala.cli.util.MaybeConfigPasswordOption

final case class PgpSecretKeyCheck(
  options: PublishSetupOptions,
  coursierCache: FileCache[Task],
  configDb: () => ConfigDb,
  logger: Logger,
  backend: SttpBackend[Identity, Any]
) extends OptionCheck {
  def kind          = OptionCheck.Kind.Signing
  def fieldName     = "pgp-secret-key"
  def directivePath = "publish" + (if (options.publishParams.setupCi) ".ci" else "") + ".secretKey"

  def check(pubOpt: BPublishOptions): Boolean = {
    val opt0 = pubOpt.retained(options.publishParams.setupCi)

    val pgpKeysFound = getPGPKeys

    opt0.repository.orElse(options.publishRepo.publishRepository).contains("github") ||
    (opt0.secretKey.isDefined ||
    (options.publishParams.ci.contains(false) && pgpKeysFound.isRight)) &&
    pgpKeysFound.exists(secPassPub => isKeyUploadedEverywhere(secPassPub._3).contains(true))
  }

  private val base64Chars = (('A' to 'Z') ++ ('a' to 'z') ++ ('0' to '9') ++ Seq('+', '/', '='))
    .map(_.toByte)
    .toSet

  // kind of meh, ideally we should know beforehand whether we are handed base64 or not
  private def maybeEncodeBase64(input: Array[Byte]): String =
    if (input.nonEmpty && input.forall(base64Chars.contains))
      new String(input.map(_.toChar))
    else
      Base64.getEncoder().encodeToString(input)

  def javaCommand: Either[BuildException, () => String] = either {
    () =>
      value(JvmUtils.javaOptions(options.sharedJvm)).javaHome(
        ArchiveCache().withCache(coursierCache),
        coursierCache,
        logger.verbosity
      ).value.javaCommand
  }

  /** Get PGP secret key, PGP password and PGP public key if possible
    */
  lazy val getPGPKeys
    : Either[BuildException, (PasswordOption, Option[PasswordOption], Option[PasswordOption])] = {
    def getPasswordOption(cliOption: Option[MaybeConfigPasswordOption])
      : Either[BuildException, Option[PasswordOption]] =
      cliOption match {
        case Some(maybeConfigPassword) =>
          for
            passwordOption <- maybeConfigPassword.configPasswordOptions().get(configDb())
          yield Some(passwordOption)
        case None => Right(None)
      }

    lazy val missingSecretKeyError = new MissingPublishOptionError(
      "publish secret key",
      "--secret-key",
      "publish.secretKey",
      configKeys = Seq(Keys.pgpSecretKey.fullName),
      extraMessage =
        "also specify publish.secretKeyPassword / --secret-key-password if needed." +
          (if (options.publishParams.setupCi)
             " Alternatively, pass --random-secret-key"
           else "")
    )

    if (options.publishParams.secretKey.isDefined)
      for {
        secretKeyOpt      <- getPasswordOption(options.publishParams.secretKey)
        secretKey         <- secretKeyOpt.toRight(missingSecretKeyError)
        secretKeyPassword <- getPasswordOption(options.publishParams.secretKeyPassword)
      } yield (
        secretKey,
        secretKeyPassword,
        options.publicKey.map(_.toConfig)
      )
    else if (options.randomSecretKey.getOrElse(false) && options.publishParams.setupCi) either {
      val maybeMail = options.randomSecretKeyMail.toRight(
        new MissingPublishOptionError(
          "the e-mail address to associate to the random key pair",
          "--random-secret-key-mail",
          ""
        )
      )

      val passwordSecret = value {
        getPasswordOption(options.publishParams.secretKeyPassword)
          .map(_.fold(ThrowawayPgpSecret.pgpPassPhrase())(_.get().toCliSigning))
      }

      val (pgpPublic, pgpSecret0) = value {
        ThrowawayPgpSecret.pgpSecret(
          value(maybeMail),
          passwordSecret,
          logger,
          coursierCache,
          value(javaCommand),
          options.scalaSigning.cliOptions()
        )
      }

      val pgpSecretBase64 = pgpSecret0.map(Base64.getEncoder.encodeToString)

      (
        PasswordOption.Value(pgpSecretBase64.toConfig),
        Some(PasswordOption.Value(passwordSecret.toConfig)),
        Some(PasswordOption.Value(pgpPublic.toConfig))
      )

    }
    else
      for {
        secretKeyOpt <- configDb().get(Keys.pgpSecretKey).wrapConfigException
        secretKey    <- secretKeyOpt.toRight(missingSecretKeyError)
        pubKeyOpt    <- configDb().get(Keys.pgpPublicKey).wrapConfigException
        passwordOpt  <- configDb().get(Keys.pgpSecretKeyPassword).wrapConfigException
      } yield (secretKey, passwordOpt, pubKeyOpt)
  }

  lazy val keyServers: Either[BuildException, Seq[Uri]] = {
    val rawKeyServers = options.sharedPgp.keyServer.filter(_.trim.nonEmpty)
    if (rawKeyServers.filter(_.trim.nonEmpty).isEmpty)
      Right(KeyServer.allDefaults)
    else
      rawKeyServers
        .map { keyServerUriStr =>
          Uri.parse(keyServerUriStr).left.map { err =>
            new MalformedCliInputError(
              s"Malformed key server URI '$keyServerUriStr': $err"
            )
          }
        }
        .sequence
        .left.map(CompositeBuildException(_))
  }

  def isKeyUploadedEverywhere(pubKeyOpt: Option[PasswordOption]): Either[BuildException, Boolean] =
    either {
      pubKeyOpt match {
        case Some(pubKey) =>
          val keyId = value {
            (new PgpProxyMaker).get().keyId(
              pubKey.get().value,
              "[generated key]",
              coursierCache,
              logger,
              value(javaCommand),
              options.scalaSigning.cliOptions()
            )
          }

          value(keyServers).forall { keyServer =>
            KeyServer.check(keyId, keyServer, backend) match
              case Right(Right(_)) => true
              case _               => false
          }
        case None => false
      }
    }

  def defaultValue(pubOpt: BPublishOptions): Either[BuildException, OptionCheck.DefaultValue] =
    either {
      val (secretKey, passwordOpt, pubKeyOpt) = value(getPGPKeys)

      val pushKey: () => Either[BuildException, Unit] = pubKeyOpt match {
        case Some(pubKey) =>
          val keyId = value {
            (new PgpProxyMaker).get().keyId(
              pubKey.get().value,
              "[generated key]",
              coursierCache,
              logger,
              value(javaCommand),
              options.scalaSigning.cliOptions()
            )
          }
          () =>
            value(keyServers)
              .map { keyServer =>
                logger.message("pgp-secret-key:")
                if (options.dummy) {
                  logger.message(s"  would upload key 0x${keyId.stripPrefix("0x")} to $keyServer")
                  Right(())
                }
                else {
                  val e: Either[BuildException, Unit] = either {
                    val checkResp = value {
                      KeyServer.check(keyId, keyServer, backend)
                        .left.map(msg =>
                          new PgpSecretKeyCheck.KeyServerError(
                            s"Error getting key $keyId from $keyServer: $msg"
                          )
                        )
                    }
                    logger.debug(s"Key server check response: $checkResp")
                    val check = checkResp.isRight
                    if (!check) {
                      val resp = value {
                        KeyServer.add(pubKey.get().value, keyServer, backend)
                          .left.map(msg =>
                            new PgpSecretKeyCheck.KeyServerError(
                              s"Error uploading key $keyId to $keyServer: $msg"
                            )
                          )
                      }
                      logger.debug(s"Key server upload response: $resp")
                      logger.message("") // printing an empty line, for readability
                      logger.message(s"  uploaded key 0x${keyId.stripPrefix("0x")} to $keyServer")
                    }
                  }
                  e
                }
              }
              .sequence
              .left.map(CompositeBuildException(_))
              .map(_ => ())
        case None =>
          logger.message(
            "Warning: no public key passed, not checking if the key needs to be uploaded to a key server."
          )
          () => Right(())
      }
      if (options.publishParams.setupCi) {
        val (passwordSetSecret, extraDirectives) = passwordOpt
          .map { p =>
            val dir    = "publish.ci.secretKeyPassword" -> "env:PUBLISH_SECRET_KEY_PASSWORD"
            val setSec = SetSecret("PUBLISH_SECRET_KEY_PASSWORD", p.get(), force = true)
            (Seq(setSec), Seq(dir))
          }
          .getOrElse((Nil, Nil))

        val keySetSecrets = Seq(SetSecret(
          "PUBLISH_SECRET_KEY",
          secretKey.get(),
          force = true
        ))

        val setSecrets = keySetSecrets ++ passwordSetSecret
        OptionCheck.DefaultValue(
          () =>
            pushKey().map(_ =>
              if (options.publishParams.setupCi) Some("env:PUBLISH_SECRET_KEY") else None
            ),
          extraDirectives,
          setSecrets
        )
      }
      else
        OptionCheck.DefaultValue(
          () =>
            pushKey().map(_ => None),
          Nil,
          Nil
        )
    }
}

object PgpSecretKeyCheck {
  final class KeyServerError(message: String) extends BuildException(message)
}
