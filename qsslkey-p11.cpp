#include <QtCore/QThread>
#include <QtCore/QFile>
#include <QtCore/QEventLoop>
#include <QtCore/QTimer>
#include <QtGui/QApplication>
#include <QtGui/QInputDialog>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QTcpServer>

#define USE_PKCS11

#ifdef USE_PKCS11
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#define HEADER_STORE_H  /* avoid openssl/store.h inclusion, break compil */
#include <openssl/engine.h>
#endif

class AuthServer : public QTcpServer
{
    Q_OBJECT
public:
    AuthServer() : socket(0) { }
    QSslSocket *socket;

protected:
    void incomingConnection(int socketDescriptor)
    {
        socket = new QSslSocket(this);

        socket->setPrivateKey("certs/key.pem",  QSsl::Rsa, QSsl::Pem, "testtest");
        socket->setLocalCertificate("certs/cert.pem");
        socket->setSocketDescriptor(socketDescriptor);
        socket->startServerEncryption();

        connect(socket, SIGNAL(encrypted()), this, SLOT(socketEncrypted()));
    }

signals:
    void authenticated();

private slots:
    void socketEncrypted()
    {
        // Very basic authentication, check that the client is using the same certificate
        if (socket->peerCertificate() != socket->localCertificate()) {
            qDebug() << socket->peerCertificate();
            qDebug() << socket->localCertificate();
            socket->abort();
        } else
            emit authenticated();
    }
};

#define VERIFY(x)                                   \
    do {                                            \
        if (!(x)) {                                 \
            fprintf(stderr, "%s failed\n", #x);     \
            return ;                                \
        }  else {                                   \
            fprintf(stderr, "%s passed\n", #x);     \
        }                                           \
    } while (0)

#ifdef USE_PKCS11
static QByteArray QByteArray_from_X509(X509 *x509)
{
    if (!x509) {
        qWarning("QSslSocketBackendPrivate::X509_to_QByteArray: null X509");
        return QByteArray();
    }

    // Use i2d_X509 to convert the X509 to an array.
    int length = i2d_X509(x509, 0);
    QByteArray array;
    array.resize(length);
    char *data = array.data();
    char **dataP = &data;
    unsigned char **dataPu = (unsigned char **)dataP;
    if (i2d_X509(x509, dataPu) < 0)
        return QByteArray();

    // Convert to Base64 - wrap at 64 characters.
    array = array.toBase64();
    QByteArray tmp;
    for (int i = 0; i <= array.size() - 64; i += 64) {
        tmp += QByteArray::fromRawData(array.data() + i, 64);
        tmp += '\n';
    }
    if (int remainder = array.size() % 64) {
        tmp += QByteArray::fromRawData(array.data() + array.size() - remainder, remainder);
        tmp += '\n';
    }

    return "-----BEGIN CERTIFICATE-----\n" + tmp + "-----END CERTIFICATE-----\n";
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    if (UI_get_string_type(uis) != UIT_PROMPT) {
        qWarning("unsupported UI string type (%u)\n", UI_get_string_type(uis));
        return 0;
    }

    QString value = QInputDialog::getText(NULL, "Enter PIN code",
                                          QString(UI_get0_output_string(uis)),
                                          QLineEdit::Password);

    UI_set_result(ui, uis, value.toAscii().data());

    return 1;
}

static ENGINE *ssl_engine = 0;

static void pkcs11_init(const QString & pkcs11_module, const QString & keyid,
                        QSslCertificate & certificate, QSslKey & key)
{
    ENGINE *e;

    /* Probably already done by Qt */
    //ERR_load_crypto_strings();
    //SSL_load_error_strings();
    //OpenSSL_add_all_algorithms();
    //SSL_library_init();
    ENGINE_load_dynamic();
    ERR_clear_error();

    e = ENGINE_by_id("dynamic");
    if (!e) {
        qWarning("Unable to load dynamic engine: %s",
                 ERR_reason_error_string(ERR_get_error()));
        goto error;
    }

    if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", "./engine_pkcs11.dll", 0) ||
        !ENGINE_ctrl_cmd_string(e, "ID", "pkcs11", 0) ||
        !ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0) ||
        !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0) ||
        !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", pkcs11_module.toLocal8Bit().data(), 0) ||
        !ENGINE_ctrl_cmd_string(e, "VERBOSE", NULL, 1) ||
        !ENGINE_init(e)
        /*!ENGINE_set_default(e, ENGINE_METHOD_ALL)*/) {
        qWarning("Unable to initialize PKCS#11 library: %s",
                 ERR_reason_error_string(ERR_get_error()));
        goto error;
    }

    { /* Load private key */
        EVP_PKEY *k;
        UI_METHOD *ui_meth = UI_create_method("PIN prompt");

        UI_method_set_reader(ui_meth, ui_read);
        k = ENGINE_load_private_key(e, keyid.toLocal8Bit().data(), ui_meth, NULL);

        if (!k) {
            qWarning("Unable to load private key from HSM: %s",
                     ERR_reason_error_string(ERR_get_error()));
            goto error;
        }

        key = QSslKey(Qt::HANDLE(k));
    }

    { /* Load certificate */
        struct {
            const char *cert_id;
            X509 *cert;
        } params = { NULL, NULL };

        if (!ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &params, NULL, 0))
            params.cert = NULL;

        if (!params.cert) {
            qWarning("Unable to load certificate from HSM");
            goto error;
        }

        certificate = QSslCertificate(QByteArray_from_X509(params.cert));
        X509_free(params.cert);
    }

    ssl_engine = e;
    return ;
error:
    if (e)
        ENGINE_free(e);
}

static void pkcs11_clear(QSslKey & key)
{
    if (!key.isNull()) {
        EVP_PKEY_free((EVP_PKEY *)key.handle());
    }
    if (ssl_engine) {
        ENGINE_finish(ssl_engine);
        ENGINE_free(ssl_engine);
    }
}
#endif
#include <QtNetwork/QSslCipher>
void test(const QString & pkcs11_module = QString(), const QString & keyid = QString())
{
    AuthServer server;
    server.listen();

    QSslSocket socket;
    QSslKey key;
    QSslCertificate cert;

    if (!pkcs11_module.isEmpty())
        pkcs11_init(pkcs11_module, keyid, cert, key);
    else {
        QFile file(QLatin1String("certs/key.pem"));
        VERIFY(file.open(QIODevice::ReadOnly));
        key = QSslKey(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, "testtest");

        QList<QSslCertificate> localCert = QSslCertificate::fromPath(QLatin1String("certs/cert.pem"));
        VERIFY(!localCert.isEmpty());
        cert = localCert.first();
    }

    VERIFY(!key.isNull());
    socket.setPrivateKey(key);

    VERIFY(cert.handle());
    socket.setLocalCertificate(cert);

    socket.connectToHostEncrypted("127.0.0.1", server.serverPort());
    socket.ignoreSslErrors();

    VERIFY(socket.waitForConnected(5000));
    VERIFY(server.waitForNewConnection(0));

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));
    QObject::connect(&socket, SIGNAL(encrypted()), &loop, SLOT(quit()));
    QObject::connect(&socket, SIGNAL(disconnected()), &loop, SLOT(quit()));
    loop.exec();

    VERIFY(socket.isEncrypted());
    VERIFY(server.socket->localCertificate() == socket.localCertificate());

    socket.abort();

    if (!pkcs11_module.isEmpty())
        pkcs11_clear(key);
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QStringList args = app.arguments();

    if (args.size() == 3)
        test(args.at(1), args.at(2));
    else
        test();

    return 0;
}

#include "qsslkey-p11.moc"
