/*
 * apdu_spy.c — LD_PRELOAD wrapper para SCardTransmit
 *
 * Intercepta SCardTransmit e loga APDUs brutos em /tmp/apdu_spy.log
 *
 * Compilar:
 *   gcc -shared -fPIC -o /tmp/apdu_spy.so apdu_spy.c -ldl $(pkg-config --cflags libpcsclite)
 *
 * Usar:
 *   LD_PRELOAD=/tmp/apdu_spy.so pkcs11-tool --module /usr/lib/safesign-private/libaetpkss.so.3 --list-objects --login
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

static FILE* logfile = NULL;

static LONG (*real_SCardTransmit)(
    SCARDHANDLE, LPCSCARD_IO_REQUEST,
    LPCBYTE, DWORD,
    LPSCARD_IO_REQUEST,
    LPBYTE, LPDWORD) = NULL;

/* Constructor — executado assim que a .so é carregada */
__attribute__((constructor))
static void spy_init() {
    logfile = fopen("/tmp/apdu_spy.log", "a");
    if (logfile) {
        fprintf(logfile, "\n===== apdu_spy carregado =====\n");
        fflush(logfile);
    }
    real_SCardTransmit = dlsym(RTLD_NEXT, "SCardTransmit");
}

LONG SCardTransmit(
    SCARDHANDLE hCard,
    LPCSCARD_IO_REQUEST pioSendPci,
    LPCBYTE pbSendBuffer,
    DWORD cbSendLength,
    LPSCARD_IO_REQUEST pioRecvPci,
    LPBYTE pbRecvBuffer,
    LPDWORD pcbRecvLength)
{

    /* Chama a função real */
    LONG rv = real_SCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength,
                                  pioRecvPci, pbRecvBuffer, pcbRecvLength);

    if (logfile) {
        /* Log APDU enviado */
        fprintf(logfile, "→ ");
        for (DWORD i = 0; i < cbSendLength; i++)
            fprintf(logfile, "%02X ", pbSendBuffer[i]);
        fprintf(logfile, "\n");

        /* Log resposta recebida */
        if (rv == SCARD_S_SUCCESS && pbRecvBuffer && pcbRecvLength && *pcbRecvLength > 0) {
            fprintf(logfile, "← ");
            for (DWORD i = 0; i < *pcbRecvLength; i++)
                fprintf(logfile, "%02X ", pbRecvBuffer[i]);
            fprintf(logfile, "\n");
        } else {
            fprintf(logfile, "← (rv=%ld)\n", rv);
        }
        fprintf(logfile, "\n");
        fflush(logfile);
    }

    return rv;
}
