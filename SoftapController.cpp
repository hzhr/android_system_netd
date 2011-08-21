/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <cutils/properties.h>
#include "private/android_filesystem_config.h"

#include "SoftapController.h"
#include "NetlinkManager.h"
#include "ResponseCode.h"

SoftapController::SoftapController() {
    mPid = 0;
    mSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mSock < 0)
        LOGE("Failed to open socket");
    memset(mIface, 0, sizeof(mIface));
    mAdHoc = false;
}

SoftapController::~SoftapController() {
    if (mSock >= 0)
        close(mSock);
}

int SoftapController::getPrivFuncNum(char *iface, const char *fname) {
    struct iwreq wrq;
    struct iw_priv_args *priv_ptr;
    int i, ret;

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.pointer = mBuf;
    wrq.u.data.length = sizeof(mBuf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    if ((ret = ioctl(mSock, SIOCGIWPRIV, &wrq)) < 0) {
        LOGE("SIOCGIPRIV failed: %d", ret);
        LOGE("Fallback to Ad-Hoc mode");
        mAdHoc = true;
        return ret;
    }
    priv_ptr = (struct iw_priv_args *)wrq.u.data.pointer;
    for(i=0;(i < wrq.u.data.length);i++) {
        if (strcmp(priv_ptr[i].name, fname) == 0)
            return priv_ptr[i].cmd;
    }
    return -1;
}

int SoftapController::startDriver(char *iface) {
    struct iwreq wrq;
    int fnum, ret;

    if (mSock < 0) {
        LOGE("Softap driver start - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        LOGD("Softap driver start - wrong interface");
        iface = mIface;
    }
    if (mAdHoc)
        return startDriver_AdHoc(iface);
    fnum = getPrivFuncNum(iface, "START");
    if (fnum < 0) {
        LOGE("Softap driver start - function not supported");
        if (mAdHoc)
            return startDriver_AdHoc(iface);
        return -1;
    }
    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.length = 0;
    wrq.u.data.pointer = mBuf;
    wrq.u.data.flags = 0;
    ret = ioctl(mSock, fnum, &wrq);
    usleep(AP_DRIVER_START_DELAY);
    LOGD("Softap driver start: %d", ret);
    return ret;
}

int SoftapController::stopDriver(char *iface) {
    struct iwreq wrq;
    int fnum, ret;

    if (mSock < 0) {
        LOGE("Softap driver stop - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        LOGD("Softap driver stop - wrong interface");
        iface = mIface;
    }
    if (mAdHoc)
        return stopDriver_AdHoc(iface);
    fnum = getPrivFuncNum(iface, "STOP");
    if (fnum < 0) {
        LOGE("Softap driver stop - function not supported");
        if (mAdHoc)
            return stopDriver_AdHoc(iface);
        return -1;
    }
    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.length = 0;
    wrq.u.data.pointer = mBuf;
    wrq.u.data.flags = 0;
    ret = ioctl(mSock, fnum, &wrq);
    LOGD("Softap driver stop: %d", ret);
    return ret;
}

int SoftapController::startSoftap() {
    struct iwreq wrq;
    pid_t pid = 1;
    int fnum, ret = 0;

    if (mPid) {
        LOGE("Softap already started");
        return 0;
    }
    if (mSock < 0) {
        LOGE("Softap startap - failed to open socket");
        return -1;
    }
    if (mAdHoc)
        return startSoftap_AdHoc();
#if 0
   if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }
#endif
    /* system("iwpriv wl0.1 AP_BSS_START"); */
    if (!pid) {
        /* start hostapd */
        return ret;
    } else {
        fnum = getPrivFuncNum(mIface, "AP_BSS_START");
        if (fnum < 0) {
            LOGE("Softap startap - function not supported");
            return -1;
        }
        strncpy(wrq.ifr_name, mIface, sizeof(wrq.ifr_name));
        wrq.u.data.length = 0;
        wrq.u.data.pointer = mBuf;
        wrq.u.data.flags = 0;
        ret = ioctl(mSock, fnum, &wrq);
        if (ret) {
            LOGE("Softap startap - failed: %d", ret);
        }
        else {
           mPid = pid;
           LOGD("Softap startap - Ok");
           usleep(AP_BSS_START_DELAY);
        }
    }
    return ret;

}

int SoftapController::stopSoftap() {
    struct iwreq wrq;
    int fnum, ret;

    if (mPid == 0) {
        LOGE("Softap already stopped");
        return 0;
    }
    if (mSock < 0) {
        LOGE("Softap stopap - failed to open socket");
        return -1;
    }
    if (mAdHoc)
        return stopSoftap_AdHoc();
    fnum = getPrivFuncNum(mIface, "AP_BSS_STOP");
    if (fnum < 0) {
        LOGE("Softap stopap - function not supported");
        return -1;
    }
    strncpy(wrq.ifr_name, mIface, sizeof(wrq.ifr_name));
    wrq.u.data.length = 0;
    wrq.u.data.pointer = mBuf;
    wrq.u.data.flags = 0;
    ret = ioctl(mSock, fnum, &wrq);
#if 0
    LOGD("Stopping Softap service");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);
#endif
    mPid = 0;
    LOGD("Softap service stopped: %d", ret);
    usleep(AP_BSS_STOP_DELAY);
    return ret;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

int SoftapController::addParam(int pos, const char *cmd, const char *arg)
{
    if (pos < 0)
        return pos;
    if ((unsigned)(pos + strlen(cmd) + strlen(arg) + 1) >= sizeof(mBuf)) {
        LOGE("Command line is too big");
        return -1;
    }
    pos += sprintf(&mBuf[pos], "%s=%s,", cmd, arg);
    return pos;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    unsigned char psk[SHA256_DIGEST_LENGTH];
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    struct iwreq wrq;
    int fnum, ret, i = 0;
    char *ssid;

    if (mSock < 0) {
        LOGE("Softap set - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap set - missing arguments");
        return -1;
    }

    if (mAdHoc)
        return setSoftap_AdHoc(argc, argv);

    fnum = getPrivFuncNum(argv[2], "AP_SET_CFG");
    if (fnum < 0) {
        LOGE("Softap set - function not supported");
        return -1;
    }

    strncpy(mIface, argv[3], sizeof(mIface));
    strncpy(wrq.ifr_name, argv[2], sizeof(wrq.ifr_name));

    /* Create command line */
    i = addParam(i, "ASCII_CMD", "AP_CFG");
    if (argc > 4) {
        ssid = argv[4];
    } else {
        ssid = (char *)"AndroidAP";
    }
    i = addParam(i, "SSID", ssid);
    if (argc > 5) {
        i = addParam(i, "SEC", argv[5]);
    } else {
        i = addParam(i, "SEC", "open");
    }
    if (argc > 6) {
        int j;
        // Use the PKCS#5 PBKDF2 with 4096 iterations
        PKCS5_PBKDF2_HMAC_SHA1(argv[6], strlen(argv[6]),
                reinterpret_cast<const unsigned char *>(ssid), strlen(ssid),
                4096, SHA256_DIGEST_LENGTH, psk);
        for (j=0; j < SHA256_DIGEST_LENGTH; j++) {
            sprintf(&psk_str[j<<1], "%02x", psk[j]);
        }
        psk_str[j<<1] = '\0';
        i = addParam(i, "KEY", psk_str);
    } else {
        i = addParam(i, "KEY", "12345678");
    }
    if (argc > 7) {
        i = addParam(i, "CHANNEL", argv[7]);
    } else {
        i = addParam(i, "CHANNEL", "6");
    }
    if (argc > 8) {
        i = addParam(i, "PREAMBLE", argv[8]);
    } else {
        i = addParam(i, "PREAMBLE", "0");
    }
    if (argc > 9) {
        i = addParam(i, "MAX_SCB", argv[9]);
    } else {
        i = addParam(i, "MAX_SCB", "8");
    }
    if ((i < 0) || ((unsigned)(i + 4) >= sizeof(mBuf))) {
        LOGE("Softap set - command is too big");
        return i;
    }
    sprintf(&mBuf[i], "END");

    wrq.u.data.length = strlen(mBuf) + 1;
    wrq.u.data.pointer = mBuf;
    wrq.u.data.flags = 0;
    /* system("iwpriv eth0 WL_AP_CFG ASCII_CMD=AP_CFG,SSID=\"AndroidAP\",SEC=\"open\",KEY=12345,CHANNEL=1,PREAMBLE=0,MAX_SCB=8,END"); */
    ret = ioctl(mSock, fnum, &wrq);
    if (ret) {
        LOGE("Softap set - failed: %d", ret);
    }
    else {
        LOGD("Softap set - Ok");
        usleep(AP_SET_CFG_DELAY);
    }
    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    struct iwreq wrq;
    int fnum, ret, i = 0;
    char *iface;

    if (mSock < 0) {
        LOGE("Softap fwrealod - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap fwreload - missing arguments");
        return -1;
    }

    if (mAdHoc)
        return fwReloadSoftap_AdHoc(argc, argv);

    iface = argv[2];
    fnum = getPrivFuncNum(iface, "WL_FW_RELOAD");
    if (fnum < 0) {
        LOGE("Softap fwReload - function not supported");
        return -1;
    }

    if (strcmp(argv[3], "AP") == 0) {
#ifdef WIFI_DRIVER_FW_AP_PATH
        sprintf(mBuf, "FW_PATH=%s", WIFI_DRIVER_FW_AP_PATH);
#endif
    } else {
#ifdef WIFI_DRIVER_FW_STA_PATH
        sprintf(mBuf, "FW_PATH=%s", WIFI_DRIVER_FW_STA_PATH);
#endif
    }
    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.length = strlen(mBuf) + 1;
    wrq.u.data.pointer = mBuf;
    wrq.u.data.flags = 0;
    ret = ioctl(mSock, fnum, &wrq);
    if (ret) {
        LOGE("Softap fwReload - failed: %d", ret);
    }
    else {
        LOGD("Softap fwReload - Ok");
    }
    return ret;
}

/************ Ad-Hoc mode support ************/
#define SUPP_CONFIG_TEMPLATE	"/system/etc/wifi/wpa_supplicant_ap.conf"
#define SUPP_CONFIG_FILE		 "/data/misc/wifi/wpa_supplicant_ap.conf"
#define SUPP_PROP_NAME			"init.svc.wpa_supp_ap"
#define SUPPLICANT_NAME		"wpa_supp_ap"

static int ensure_config_file_exists()
{
    char buf[2048];
    int srcfd, destfd;
    int nread;

    if (access(SUPP_CONFIG_FILE, R_OK|W_OK) == 0) {
        return 0;
    } else if (errno != ENOENT) {
        LOGE("Cannot access \"%s\": %s", SUPP_CONFIG_FILE, strerror(errno));
        return -1;
    }

    srcfd = open(SUPP_CONFIG_TEMPLATE, O_RDONLY);
    if (srcfd < 0) {
        LOGE("Cannot open \"%s\": %s", SUPP_CONFIG_TEMPLATE, strerror(errno));
        return -1;
    }

    destfd = open(SUPP_CONFIG_FILE, O_CREAT|O_WRONLY, 0660);
    if (destfd < 0) {
        close(srcfd);
        LOGE("Cannot create \"%s\": %s", SUPP_CONFIG_FILE, strerror(errno));
        return -1;
    }

    while ((nread = read(srcfd, buf, sizeof(buf))) != 0) {
        if (nread < 0) {
            LOGE("Error reading \"%s\": %s", SUPP_CONFIG_TEMPLATE, strerror(errno));
            close(srcfd);
            close(destfd);
            unlink(SUPP_CONFIG_FILE);
            return -1;
        }
        write(destfd, buf, nread);
    }

    close(destfd);
    close(srcfd);

    if (chown(SUPP_CONFIG_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
             SUPP_CONFIG_FILE, AID_WIFI, strerror(errno));
        unlink(SUPP_CONFIG_FILE);
        return -1;
    }
    return 0;
}

static int rename_netif(const char *old_if, const char *new_if)
{
	int sk;
	struct ifreq ifr;
	int loop;
	int err;

	LOGD("changing net interface name from '%s' to '%s'\n", old_if, new_if);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err = -errno;
		LOGE("error opening socket: %d\n", errno);
		return err;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, old_if, IFNAMSIZ);
	strncpy(ifr.ifr_newname, new_if, IFNAMSIZ);
	err = ioctl(sk, SIOCSIFNAME, &ifr);
	if (err == 0) {
		LOGD("renamed network interface %s to %s OK\n", ifr.ifr_name, ifr.ifr_newname);
		goto out;
	}

	/* keep trying if the destination interface name already exists */
	err = -errno;
	if (err != -EEXIST)
		goto out;

	/* free our own name, another process may wait for us */
	snprintf(ifr.ifr_newname, IFNAMSIZ, "wl0.1_rename");
	err = ioctl(sk, SIOCSIFNAME, &ifr);
	if (err < 0) {
		err = -errno;
		goto out;
	}

	/* wait a maximum of 90 seconds for our target to become available */
	strncpy(ifr.ifr_name, ifr.ifr_newname, IFNAMSIZ);
	strncpy(ifr.ifr_newname, new_if, IFNAMSIZ);
	loop = 90 * 20;
	while (loop--) {
		const struct timespec duration = { 0, 1000 * 1000 * 1000 / 20 };

		LOGD("wait for netif '%s' to become free, loop=%i\n", new_if, (90 * 20) - loop);
		nanosleep(&duration, NULL);

		err = ioctl(sk, SIOCSIFNAME, &ifr);
		if (err == 0) {
			LOGD("renamed network interface %s to %s OK\n", ifr.ifr_name, ifr.ifr_newname);
			break;
		}
		err = -errno;
		if (err != -EEXIST)
			break;
	}

out:
	if (err < 0)
		LOGE("error changing net interface name %s to %s: %m\n", ifr.ifr_name, ifr.ifr_newname);
	close(sk);
	return err;
}

int SoftapController::startDriver_AdHoc(char *iface) {
    int ret = 0;
    LOGD("Softap driver start (Ad-Hoc mode): %d", ret);
    return ret;
}

int SoftapController::stopDriver_AdHoc(char *iface) {
    int ret = 0;
    LOGD("Softap driver stop (Ad-Hoc mode): %d", ret);
    return ret;
}

int SoftapController::startSoftap_AdHoc() {
    int ret = 0;
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 200; /* wait at most 20 seconds for completion */

    /* /system/bin/wpa_supplicant -B -Dwext -iwl0.1 -dd -c /data/misc/wifi/wpa_supplicant_ap.conf  */
    /* Check whether already running */
    if (property_get(SUPP_PROP_NAME, supp_status, NULL)
            && strcmp(supp_status, "running") == 0) {
        return 0;
    }

    /* Before starting the daemon, make sure its config file exists */
    if ((ret = ensure_config_file_exists()) < 0) {
        LOGE("Wi-Fi will not be enabled");
        return -1;
    }

    property_set("ctl.start", SUPPLICANT_NAME);
    sched_yield();

    while (count-- > 0) {
        if (property_get(SUPP_PROP_NAME, supp_status, NULL)) {
            if (strcmp(supp_status, "running") == 0) {
                mPid = 1;
                LOGD("Softap startap (Ad-Hoc mode) - Ok");
                usleep(AP_BSS_START_DELAY);
                return 0;
            }
        }
        usleep(100000);
    }

    LOGE("Softap startap (Ad-Hoc mode) - failed: %d", ret);
    return ret;
}

int SoftapController::stopSoftap_AdHoc() {
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50; /* wait at most 5 seconds for completion */

    /* Check whether supplicant already stopped */
    if (property_get(SUPP_PROP_NAME, supp_status, NULL)
        && strcmp(supp_status, "stopped") == 0) {
        return 0;
    }

    property_set("ctl.stop", SUPPLICANT_NAME);
    sched_yield();

    while (count-- > 0) {
        if (property_get(SUPP_PROP_NAME, supp_status, NULL)) {
            if (strcmp(supp_status, "stopped") == 0) {
                mPid = 0;
                usleep(AP_BSS_STOP_DELAY);

                /* rename back wl0.1 to eth0 */
                //rename_netif(mIface, mBuf);

                LOGD("Softap service stopped (Ad-Hoc mode) - OK");
                return 0;
            }
        }
        usleep(100000);
    }

    LOGE("Softap service stopped (Ad-Hoc mode) - failed: %d", -1);
    return -1;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 */
int SoftapController::setSoftap_AdHoc(int argc, char *argv[]) {
    unsigned char psk[SHA256_DIGEST_LENGTH];
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    bool is_psk = false;
    int i = 0, channel = 0;
    char *ssid;
    FILE *fp;

    strncpy(mBuf, argv[2], sizeof(mBuf));
    strncpy(mIface, argv[3], sizeof(mIface));

    /* gen wpa_supplicant.conf */
    fp = fopen(SUPP_CONFIG_FILE, "w");
    if (!fp) {
        LOGE("setSoftap_AdHoc: write file %s error", SUPP_CONFIG_FILE);
        return -1;
    }

    fprintf(fp, "update_config=0\n");
    fprintf(fp, "ctrl_interface=/data/system/wpa_supplicant\n");
    fprintf(fp, "eapol_version=1\n");
    fprintf(fp, "ap_scan=2\n");
    fprintf(fp, "fast_reauth=0\n");
    fprintf(fp, "network={\n");

    if (argc > 4) {
        ssid = argv[4];
    } else {
        ssid = (char *)"AndroidAP";
    }
    fprintf(fp, "ssid=\"%s\"\n", ssid);
    fprintf(fp, "scan_ssid=1\n");
    fprintf(fp, "mode=1\n");

    if (argc > 5) {
        if (!strcmp(argv[5], "open"))
            fprintf(fp, "key_mgmt=NONE\n");
        else if (!strcmp(argv[5], "wpa2-psk")) {
            is_psk = true;
            fprintf(fp, "key_mgmt=WPA-PSK\n");
        } else
            fprintf(fp, "key_mgmt=NONE\n");
    } else {
        fprintf(fp, "key_mgmt=NONE\n");
    }

    if (is_psk) {
        fprintf(fp, "group=WEP104\n"); //FIXME
        fprintf(fp, "auth_alg=SHARED\n"); //FIXME
    }

    if (argc > 6 && is_psk) {
        int j;
        // Use the PKCS#5 PBKDF2 with 4096 iterations
        PKCS5_PBKDF2_HMAC_SHA1(argv[6], strlen(argv[6]),
                reinterpret_cast<const unsigned char *>(ssid), strlen(ssid),
                4096, SHA256_DIGEST_LENGTH, psk);
        for (j=0; j < SHA256_DIGEST_LENGTH; j++) {
            sprintf(&psk_str[j<<1], "%02x", psk[j]);
        }
        psk_str[j<<1] = '\0';
        //fprintf(fp, "wep_key0=\"%s\"\n", psk_str);
        fprintf(fp, "psk=\"%s\"\n", psk_str); // key_mgmt=WPA-PSK
    } else if (is_psk) {
        //fprintf(fp, "wep_key0=\"12345678\"\n");
        fprintf(fp, "psk=\"12345678\"\n"); // key_mgmt=WPA-PSK
    }

    fprintf(fp, "}\n");
    fclose(fp);

    if (chown(SUPP_CONFIG_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
             SUPP_CONFIG_FILE, AID_WIFI, strerror(errno));
        unlink(SUPP_CONFIG_FILE);
        return -1;
    }

    if (argc > 7) {
        channel = atoi(argv[7]);
    } else {
        channel = 6;
    }

    /*if (argc > 8) {
        i = addParam(i, "PREAMBLE", argv[8]);
    } else {
        i = addParam(i, "PREAMBLE", "0");
    }
    if (argc > 9) {
        i = addParam(i, "MAX_SCB", argv[9]);
    } else {
        i = addParam(i, "MAX_SCB", "8");
    }*/

    /* rename eth0 to wl0.1 */
    if (rename_netif(mBuf, mIface) < 0)
        return -1;

    snprintf(mBuf, sizeof(mBuf), "Iface removed %s", mBuf);
    NetlinkManager::Instance()->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            mBuf, false);
    snprintf(mBuf, sizeof(mBuf), "Iface added %s", mIface);
    NetlinkManager::Instance()->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            mBuf, false);

    /* system("iwpriv eth0 WL_AP_CFG ASCII_CMD=AP_CFG,SSID=\"AndroidAP\",SEC=\"open\",KEY=12345,CHANNEL=1,PREAMBLE=0,MAX_SCB=8,END"); */

    /* Setting ad-hoc mode */
    sprintf(mBuf, "/system/bin/iwconfig %s mode ad-hoc", mIface);
    system(mBuf);
    LOGD("%s", mBuf);
    usleep(AP_SET_CFG_DELAY);
    /* Setting essid */
    sprintf(mBuf, "/system/bin/iwconfig %s essid %s", mIface, ssid);
    system(mBuf);
    LOGD("%s", mBuf);
    usleep(AP_SET_CFG_DELAY);
    /* Setting channel */
    sprintf(mBuf, "/system/bin/iwconfig %s channel %d", mIface, channel);
    system(mBuf);
    LOGD("%s", mBuf);
    usleep(AP_SET_CFG_DELAY);
    /* Setting transmit power */
    /* sprintf(mBuf, "/system/bin/iwconfig %s txpower %s", mIface, xx); */
    sprintf(mBuf, "/system/bin/iwconfig %s commit", mIface);
    system(mBuf);
    LOGD("%s", mBuf);
    usleep(AP_SET_CFG_DELAY*2);

    /* WEP-Encryption  */
    /* if "wifi.encryption" == "wep"
      set by iwconfig:
        /system/bin/iwconfig %s key s:"xxx"
        /system/bin/iwconfig %s key restricted"
        /system/bin/iwconfig %s commit
     or by wpa_supplicant */

    LOGD("Softap set (Ad-Hoc mode) - Ok");
    return 0;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap_AdHoc(int argc, char *argv[])
{
    LOGD("Softap fwReload (Ad-Hoc mode) - Ok");
    return 0;
}
