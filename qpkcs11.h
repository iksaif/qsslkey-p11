#ifndef QPKCS11
# define QPKCS11

#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>

class QAuthenticator;

class QPkcs11 : public QObject {
	Q_OBJECT

public:
	QPkcs11(const QString & module, QObject *parent = 0);
	~QPkcs11();

	QSslCertificate loadCertificate(const QString & label = "");
	QSslKey loadKey(const QString & label = "");

	/* FIXME: make that private, this is used by the UI callback */
	QString authenticationRequired(const QString & prompt);

signals:
	void authenticationRequired(const QString & prompt, QAuthenticator *authenticator);

private:
	void init();

	static QByteArray QByteArray_from_X509(X509 *cert);
	static UI_METHOD *s_uiMethod;

	QString m_module;
	ENGINE *m_engine;
};

#endif /* !QPKCS11 */