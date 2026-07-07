#!/usr/bin/env bash
# Internal helper — called by gen-msvcp140-stubs.sh to find delta.
# Extracts current resolve entries and diffs against the probe output.

EXISTING=$(grep -oP '"[^"]+"' /weave/weave-msvcp140/src/lib.rs | grep -v '^"[a-z_]' | sort -u)

cat > /tmp/gen_list.txt << 'GENEOF'
??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@AEBV01@@Z
??0?$codecvt@_SDU_Mbstatet@@@std@@QEAA@_K@Z
??0?$codecvt@_UDU_Mbstatet@@@std@@QEAA@_K@Z
??0_Locinfo@std@@QEAA@HPEBD@Z
??1?$codecvt@_SDU_Mbstatet@@@std@@MEAA@XZ
??1?$codecvt@_UDU_Mbstatet@@@std@@MEAA@XZ
??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAH@Z
??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAJ@Z
??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAN@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@F@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@G@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@M@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@N@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEBX@Z
??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_J@Z
?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z
?_Getcat@?$ctype@_W@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z
?_Getcoll@_Locinfo@std@@QEBA?AU_Collvec@@XZ
?_Getname@_Locinfo@std@@QEBAPEBDXZ
?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z
?_Makeloc@_Locimp@locale@std@@CAPEAV123@AEBV_Locinfo@3@HPEAV123@PEBV23@@Z
?_New_Locimp@_Locimp@locale@std@@CAPEAV123@_N@Z
?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ
?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA
?_Winerror_map@std@@YAHH@Z
?_Xoverflow_error@std@@YAXPEBD@Z
?_Xregex_error@std@@YAXW4error_type@regex_constants@1@@Z
?_Xruntime_error@std@@YAXPEBD@Z
?__ExceptionPtrToBool@@YA_NPEBX@Z
?bad@ios_base@std@@QEBA_NXZ
?c_str@?$_Yarn@D@std@@QEBAPEBDXZ
?classic@locale@std@@SAAEBV12@XZ
?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
?eof@ios_base@std@@QEBA_NXZ
?fill@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBA_WXZ
?flush@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@XZ
?gcount@?$basic_istream@DU?$char_traits@D@std@@@std@@QEBA_JXZ
?id@?$collate@D@std@@2V0locale@2@A
?id@?$collate@_W@std@@2V0locale@2@A
?id@?$ctype@D@std@@2V0locale@2@A
?id@?$ctype@_W@std@@2V0locale@2@A
?imbue@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAA?AVlocale@2@AEBV32@@Z
?in@?$codecvt@_WDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEA_W3AEAPEA_W@Z
?init@?$basic_ios@DU?$char_traits@D@std@@@std@@IEAAXPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@_N@Z
?is@?$ctype@_W@std@@QEBA_NF_W@Z
?out@?$codecvt@_SDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_S1AEAPEB_SPEAD3AEAPEAD@Z
?out@?$codecvt@_UDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_U1AEAPEB_UPEAD3AEAPEAD@Z
?overflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@Z
?peek@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ
?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@PEAV32@@Z
?rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@2@XZ
?resetiosflags@std@@YA?AU?$_Smanip@H@1@H@Z
?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z
?setf@ios_base@std@@QEAAHHH@Z
?setprecision@std@@YA?AU?$_Smanip@_J@1@_J@Z
?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z
?sputc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAG_W@Z
?sputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_JPEB_W_J@Z
?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ
?tie@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$basic_ostream@_WU?$char_traits@_W@std@@@2@XZ
?tolower@?$ctype@D@std@@QEBADD@Z
?tolower@?$ctype@D@std@@QEBAPEBDPEADPEBD@Z
?tolower@?$ctype@_W@std@@QEBAPEB_WPEA_WPEB_W@Z
?tolower@?$ctype@_W@std@@QEBA_W_W@Z
_Cnd_broadcast
_Cnd_wait
_Strcoll
_Strxfrm
_Thrd_hardware_concurrency
_Thrd_yield
_Wcscoll
_Wcsxfrm
GENEOF

echo "=== NEW MSVCP140 STUBS (not in resolve map) ==="
while IFS= read -r sym; do
    [ -z "$sym" ] && continue
    full="\"$sym\""
    if ! echo "$EXISTING" | grep -qF "$full"; then
        echo "        | \"$sym\""
    fi
done < /tmp/gen_list.txt

echo ""
echo "=== DATA SYMBOLS (need data addr, not noop) ==="
echo '?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A'
echo '?id@?$collate@D@std@@2V0locale@2@A'
echo '?id@?$collate@_W@std@@2V0locale@2@A'
echo '?id@?$ctype@D@std@@2V0locale@2@A'
echo '?id@?$ctype@_W@std@@2V0locale@2@A'
echo '?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA'

echo ""
echo "=== VCRUNTIME140 STUBS (add to weave-audacity resolve) ==="
echo '__RTCastToVoid'
echo '_set_se_translator'
