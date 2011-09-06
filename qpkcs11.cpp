#include <QtNetwork/QAuthenticator>

#include "qpkcs11.h"
#include <QDebug>

UI_METHOD * QPkcs11::s_uiMethod = 0;

struct qpkcs11_callback_data {
	const void *engine_pkcs11_password;
	const void *engine_pkcs11_prompt_info;
	QPkcs11 *qpkcs11;
};

static int qpkcs11_ui_read(UI *ui, UI_STRING *uis)
{
    if (UI_get_string_type(uis) != UIT_PROMPT) {
        qWarning("unsupported UI string type (%u)\n", UI_get_string_type(uis));
        return 0;
    }

	struct qpkcs11_callback_data *data = (struct qpkcs11_callback_data *)UI_get_app_data(ui);

	if (!data->qpkcs11)
        return 0;

	QString prompt(UI_get0_output_string(uis));
	QString pin = data->qpkcs11->authenticationRequired(prompt);

	UI_set_result(ui, uis, pin.toLocal8Bit().data());

    return 1;
}

QPkcs11::QPkcs11(const QString & module, QObject *parent)
	: QObject(parent),
	  m_module(module),
	  m_engine(0)
{
	init();
}

QPkcs11::~QPkcs11()
{
	if (m_engine) {
        ENGINE_finish(m_engine);
        ENGINE_free(m_engine);
    }
}

QSslCertificate
QPkcs11::loadCertificate(const QString & label)
{
	QSslCertificate certificate;

	struct {
		const char *cert_id;
        X509 *cert;
    } params = { NULL, NULL };

	if (!label.isEmpty())
		params.cert_id = label.toLocal8Bit().data();

    if (!ENGINE_ctrl_cmd(m_engine, "LOAD_CERT_CTRL", 0, &params, NULL, 0))
        params.cert = NULL;

    if (!params.cert) {
        qWarning("Unable to load certificate from HSM");
	} else {
		certificate = QSslCertificate(QByteArray_from_X509(params.cert));
		X509_free(params.cert);
	}

	return certificate;
}

QSslKey
QPkcs11::loadKey(const QString & label)
{
    EVP_PKEY *k;
	QSslKey key;
	struct qpkcs11_callback_data data;

	data.engine_pkcs11_password = NULL;
	data.engine_pkcs11_prompt_info = NULL;
	data.qpkcs11 = this;

	if (!s_uiMethod) {
		s_uiMethod = UI_create_method("QPkcs11 PIN prompt");
        UI_method_set_reader(s_uiMethod, qpkcs11_ui_read);
	}

    k = ENGINE_load_private_key(m_engine, label.toLocal8Bit().data(), s_uiMethod, &data);

	if (!k) {
        qWarning("Unable to load private key from HSM: %s",
                 ERR_reason_error_string(ERR_get_error()));
    } else
	    key = QSslKey(Qt::HANDLE(k));

	return key;
}

QByteArray QPkcs11::QByteArray_from_X509(X509 *x509)
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

void QPkcs11::init()
{
    ENGINE *e;/*
	    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();*/
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
        !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", m_module.toLocal8Bit().data(), 0) ||
        !ENGINE_ctrl_cmd_string(e, "VERBOSE", NULL, 1) ||
        !ENGINE_init(e)) {
        qWarning("Unable to initialize PKCS#11 library: %s",
                 ERR_reason_error_string(ERR_get_error()));
        goto error;
    }

	m_engine = e;
    return ;
error:
    if (e)
        ENGINE_free(e);
}

QString
QPkcs11::authenticationRequired(const QString & prompt)
{
	QAuthenticator authenticator;
	qDebug() << "signal" << prompt;
	emit authenticationRequired(prompt, &authenticator);
	return authenticator.password();
}
