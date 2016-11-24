/*
 * Copyright (C) by Daniel Molkentin <danimo@owncloud.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include "account.h"
#include "cookiejar.h"
#include "networkjobs.h"
#include "configfile.h"
#include "accessmanager.h"
#include "creds/abstractcredentials.h"
#include "../3rdparty/certificates/p12topem.h"
#include "capabilities.h"
#include "theme.h"

#include <QSettings>
#include <QMutex>
#include <QNetworkReply>
#include <QNetworkAccessManager>
#include <QSslSocket>
#include <QNetworkCookieJar>
#include <QFileInfo>
#include <QDir>
#include <QDebug>
#include <QSslKey>

namespace OCC {


Account::Account(QObject *parent)
    : QObject(parent)
    , _capabilities(QVariantMap())
    , _davPath( Theme::instance()->webDavPath() )
{
    qRegisterMetaType<AccountPtr>("AccountPtr");
}

AccountPtr Account::create()
{
    AccountPtr acc = AccountPtr(new Account);
    acc->setSharedThis(acc);
    return acc;
}

Account::~Account()
{
}

QString Account::davPath() const
{
    // make sure to have a trailing slash
    if( !_davPath.endsWith('/') ) {
        QString dp(_davPath);
        dp.append('/');
        return dp;
    }
    return _davPath;
}

void Account::setSharedThis(AccountPtr sharedThis)
{
    _sharedThis = sharedThis.toWeakRef();
}

AccountPtr Account::sharedFromThis()
{
    return _sharedThis.toStrongRef();
}

QString Account::davUser() const
{
    return _davUser.isEmpty() ? _credentials->user() : _davUser;
}

void Account::setDavUser(const QString &newDavUser)
{
    _davUser = newDavUser;
}

QString Account::davFilesPath() const
{
    //TODO DO NOT HARCODE PATH, GET IT FROM THE SERVER!!!!
    QString dfp("/remote.php/dav/files/");
    dfp.append(_credentials->user());
    return dfp;
}

QString Account::displayName() const
{
    QString dn = QString("%1@%2").arg(davUser(), _url.host());
    int port = url().port();
    if (port > 0 && port != 80 && port != 443) {
        dn.append(QLatin1Char(':'));
        dn.append(QString::number(port));
    }
    return dn;
}

QString Account::id() const
{
    return _id;
}

AbstractCredentials *Account::credentials() const
{
    return _credentials.data();
}

void Account::setCredentials(AbstractCredentials *cred)
{
    // set active credential manager
    QNetworkCookieJar *jar = 0;
    if (_am) {
        jar = _am->cookieJar();
        jar->setParent(0);

        _am = QSharedPointer<QNetworkAccessManager>();
    }

    // The order for these two is important! Reading the credential's
    // settings accesses the account as well as account->_credentials,
    // so deleteLater must be used.
    _credentials = QSharedPointer<AbstractCredentials>(cred, &QObject::deleteLater);
    cred->setAccount(this);

    _am = QSharedPointer<QNetworkAccessManager>(_credentials->getQNAM(), &QObject::deleteLater);

    if (jar) {
        _am->setCookieJar(jar);
    }
    connect(_am.data(), SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
            SLOT(slotHandleSslErrors(QNetworkReply*,QList<QSslError>)));
    connect(_am.data(), SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));
    connect(_credentials.data(), SIGNAL(fetched()),
            SLOT(slotCredentialsFetched()));
    connect(_credentials.data(), SIGNAL(asked()),
            SLOT(slotCredentialsAsked()));
}

QUrl Account::davUrl() const
{
    return Utility::concatUrlPath(url(), davPath());
}

void Account::clearCookieJar()
{
    Q_ASSERT(qobject_cast<CookieJar*>(_am->cookieJar()));
    static_cast<CookieJar*>(_am->cookieJar())->clearSessionCookies();
}

/*! This shares our official cookie jar (containing all the tasty
    authentication cookies) with another QNAM while making sure
    of not losing its ownership. */
void Account::lendCookieJarTo(QNetworkAccessManager *guest)
{
    auto jar = _am->cookieJar();
    auto oldParent = jar->parent();
    guest->setCookieJar(jar); // takes ownership of our precious cookie jar
    jar->setParent(oldParent); // takes it back
}

void Account::resetNetworkAccessManager()
{
    if (!_credentials || !_am) {
        return;
    }

    qDebug() << "Resetting QNAM";
    QNetworkCookieJar* jar = _am->cookieJar();

    // Use a QSharedPointer to allow locking the life of the QNAM on the stack.
    // Make it call deleteLater to make sure that we can return to any QNAM stack frames safely.
    _am = QSharedPointer<QNetworkAccessManager>(_credentials->getQNAM(), &QObject::deleteLater);

    _am->setCookieJar(jar); // takes ownership of the old cookie jar
    connect(_am.data(), SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
            SLOT(slotHandleSslErrors(QNetworkReply*,QList<QSslError>)));
    connect(_am.data(), SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));
}

QNetworkAccessManager *Account::networkAccessManager()
{
    return _am.data();
}

QNetworkReply *Account::headRequest(const QString &relPath)
{
    return headRequest(Utility::concatUrlPath(url(), relPath));
}

QNetworkReply *Account::headRequest(const QUrl &url)
{
    QNetworkRequest request(url);
#if QT_VERSION > QT_VERSION_CHECK(4, 8, 4)
    request.setSslConfiguration(this->getOrCreateSslConfig());
#endif
    return _am->head(request);
}

QNetworkReply *Account::getRequest(const QString &relPath)
{
    return getRequest(Utility::concatUrlPath(url(), relPath));
}

QNetworkReply *Account::getRequest(const QUrl &url)
{
    QNetworkRequest request(url);
#if QT_VERSION > QT_VERSION_CHECK(4, 8, 4)
    request.setSslConfiguration(this->getOrCreateSslConfig());
#endif
    return _am->get(request);
}

QNetworkReply *Account::deleteRequest( const QUrl &url)
{
    QNetworkRequest request(url);
#if QT_VERSION > QT_VERSION_CHECK(4, 8, 4)
    request.setSslConfiguration(this->getOrCreateSslConfig());
#endif
    return _am->deleteResource(request);
}

QNetworkReply *Account::davRequest(const QByteArray &verb, const QString &relPath, QNetworkRequest req, QIODevice *data)
{
    return davRequest(verb, Utility::concatUrlPath(davUrl(), relPath), req, data);
}

QNetworkReply *Account::davRequest(const QByteArray &verb, const QUrl &url, QNetworkRequest req, QIODevice *data)
{
    req.setUrl(url);
#if QT_VERSION > QT_VERSION_CHECK(4, 8, 4)
    req.setSslConfiguration(this->getOrCreateSslConfig());
#endif
    return _am->sendCustomRequest(req, verb, data);
}

QNetworkReply *Account::multipartRequest(const QString &relPath, QNetworkRequest req, QHttpMultiPart *multiPart)
{
    return multipartRequest(Utility::concatUrlPath(url(), relPath), req, multiPart);
}

QNetworkReply *Account::multipartRequest(const QUrl &url, QNetworkRequest req, QHttpMultiPart *multiPart)
{
    req.setUrl(url);
#if QT_VERSION > QT_VERSION_CHECK(4, 8, 4)
    req.setSslConfiguration(this->getOrCreateSslConfig());
#endif
    return _am->post(req, multiPart);
}

void Account::setCertificate(const QByteArray certficate, const QString privateKey)
{
    _pemCertificate=certficate;
    _pemPrivateKey=privateKey;
}

void Account::setSslConfiguration(const QSslConfiguration &config)
{
    _sslConfiguration = config;
}

QSslConfiguration Account::getOrCreateSslConfig()
{
    if (!_sslConfiguration.isNull()) {
        // Will be set by CheckServerJob::finished()
        // We need to use a central shared config to get SSL session tickets
        return _sslConfiguration;
    }

    // if setting the client certificate fails, you will probably get an error similar to this:
    //  "An internal error number 1060 happened. SSL handshake failed, client certificate was requested: SSL error: sslv3 alert handshake failure"
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    QSslCertificate sslClientCertificate;
    
    ConfigFile cfgFile;
    if(!cfgFile.certificatePath().isEmpty() && !cfgFile.certificatePasswd().isEmpty()) {
        resultP12ToPem certif = p12ToPem(cfgFile.certificatePath().toStdString(), cfgFile.certificatePasswd().toStdString());
        QString s = QString::fromStdString(certif.Certificate);
        QByteArray ba = s.toLocal8Bit();
        this->setCertificate(ba, QString::fromStdString(certif.PrivateKey));
    }
    if((!_pemCertificate.isEmpty())&&(!_pemPrivateKey.isEmpty())) {
        // Read certificates
        QList<QSslCertificate> sslCertificateList = QSslCertificate::fromData(_pemCertificate, QSsl::Pem);
        if(sslCertificateList.length() != 0) {
            sslClientCertificate = sslCertificateList.takeAt(0);
        }
        // Read key from file
        QSslKey privateKey(_pemPrivateKey.toLocal8Bit(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey , "");

        // SSL configuration
        sslConfig.setCaCertificates(QSslSocket::systemCaCertificates());
        sslConfig.setLocalCertificate(sslClientCertificate);
        sslConfig.setPrivateKey(privateKey);
        qDebug() << "Added SSL client certificate to the query";
    }

#if QT_VERSION > QT_VERSION_CHECK(5, 2, 0)
    // Try hard to re-use session for different requests
    sslConfig.setSslOption(QSsl::SslOptionDisableSessionTickets, false);
    sslConfig.setSslOption(QSsl::SslOptionDisableSessionSharing, false);
    sslConfig.setSslOption(QSsl::SslOptionDisableSessionPersistence, false);
#endif

    return sslConfig;
}

void Account::setApprovedCerts(const QList<QSslCertificate> certs)
{
    _approvedCerts = certs;
}

void Account::addApprovedCerts(const QList<QSslCertificate> certs)
{
    _approvedCerts += certs;
}

void Account::resetRejectedCertificates()
{
    _rejectedCertificates.clear();
}

void Account::setSslErrorHandler(AbstractSslErrorHandler *handler)
{
    _sslErrorHandler.reset(handler);
}

void Account::setUrl(const QUrl &url)
{
    _url = url;
}

QVariant Account::credentialSetting(const QString &key) const
{
    if (_credentials) {
        QString prefix = _credentials->authType();
        QString value = _settingsMap.value(prefix+"_"+key).toString();
        if (value.isEmpty()) {
            value = _settingsMap.value(key).toString();
        }
        return value;
    }
    return QVariant();
}

void Account::setCredentialSetting(const QString &key, const QVariant &value)
{
    if (_credentials) {
        QString prefix = _credentials->authType();
        _settingsMap.insert(prefix+"_"+key, value);
    }
}

void Account::slotHandleSslErrors(QNetworkReply *reply , QList<QSslError> errors)
{
    NetworkJobTimeoutPauser pauser(reply);
    QString out;
    QDebug(&out) << "SSL-Errors happened for url " << reply->url().toString();
    foreach(const QSslError &error, errors) {
        QDebug(&out) << "\tError in " << error.certificate() << ":"
                     << error.errorString() << "("<< error.error() << ")" << "\n";
    }

    bool allPreviouslyRejected = true;
    foreach (const QSslError &error, errors) {
        if (!_rejectedCertificates.contains(error.certificate())) {
            allPreviouslyRejected = false;
        }
    }

    // If all certs have previously been rejected by the user, don't ask again.
    if( allPreviouslyRejected ) {
        qDebug() << out << "Certs not trusted by user decision, returning.";
        return;
    }

    QList<QSslCertificate> approvedCerts;
    if (_sslErrorHandler.isNull() ) {
        qDebug() << out << Q_FUNC_INFO << "called without valid SSL error handler for account" << url();
        return;
    }

    // SslDialogErrorHandler::handleErrors will run an event loop that might execute
    // the deleteLater() of the QNAM before we have the chance of unwinding our stack.
    // Keep a ref here on our stackframe to make sure that it doesn't get deleted before
    // handleErrors returns.
    QSharedPointer<QNetworkAccessManager> qnamLock = _am;

    if (_sslErrorHandler->handleErrors(errors, reply->sslConfiguration(), &approvedCerts, sharedFromThis())) {
        QSslSocket::addDefaultCaCertificates(approvedCerts);
        addApprovedCerts(approvedCerts);
        emit wantsAccountSaved(this);
        // all ssl certs are known and accepted. We can ignore the problems right away.
//         qDebug() << out << "Certs are known and trusted! This is not an actual error.";

        // Warning: Do *not* use ignoreSslErrors() (without args) here:
        // it permanently ignores all SSL errors for this host, even
        // certificate changes.
        reply->ignoreSslErrors(errors);
    } else {
        // Mark all involved certificates as rejected, so we don't ask the user again.
        foreach (const QSslError &error, errors) {
            if (!_rejectedCertificates.contains(error.certificate())) {
                _rejectedCertificates.append(error.certificate());
            }
        }
        // if during normal operation, a new certificate was MITM'ed, and the user does not
        // ACK it, the running request must be aborted and the QNAM must be reset, to not
        // treat the new cert as granted. See bug #3283
        reply->abort();
        resetNetworkAccessManager();
        return;
    }
}

void Account::slotCredentialsFetched()
{
    emit credentialsFetched(_credentials.data());
}

void Account::slotCredentialsAsked()
{
    emit credentialsAsked(_credentials.data());
}

void Account::handleInvalidCredentials()
{
    emit invalidCredentials();
}

const Capabilities &Account::capabilities() const
{
    return _capabilities;
}

void Account::setCapabilities(const QVariantMap &caps)
{
    _capabilities = Capabilities(caps);
}

QString Account::serverVersion() const
{
    return _serverVersion;
}

int Account::serverVersionInt() const
{
    // FIXME: Use Qt 5.5 QVersionNumber
    auto components = serverVersion().split('.');
    return  (components.value(0).toInt() << 16)
                   + (components.value(1).toInt() << 8)
            + components.value(2).toInt();
}

bool Account::serverVersionUnsupported() const
{
    if (serverVersionInt() == 0) {
        // not detected yet, assume it is fine.
        return false;
    }
    return serverVersionInt() < 0x070000;
}

void Account::setServerVersion(const QString& version)
{
    if (version == _serverVersion) {
        return;
    }

    auto oldServerVersion = _serverVersion;
    _serverVersion = version;
    emit serverVersionChanged(this, oldServerVersion, version);
}

bool Account::rootEtagChangesNotOnlySubFolderEtags()
{
    return (serverVersionInt() >= 0x080100);
}

void Account::setNonShib(bool nonShib)
{
    if( nonShib ) {
        _davPath = Theme::instance()->webDavPathNonShib();
    } else {
        _davPath = Theme::instance()->webDavPath();
    } 
}

bool Account::bundledRequestsEnabled() const
{
    return _capabilities.bundledRequest();
}

} // namespace OCC
