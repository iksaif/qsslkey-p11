TEMPLATE = app
TARGET = 
DEPENDPATH += .
INCLUDEPATH += .
QT += network
CONFIG += console

# OpenSSL
INCLUDEPATH += -I D:/dev/commonit/openssl/include/
LIBS += -LD:/dev/commonit/openssl/lib/VC -llibeay32MD -lssleay32MD

SOURCES += qsslkey-p11.cpp
