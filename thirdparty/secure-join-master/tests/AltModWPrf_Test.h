#pragma once

#include "cryptoTools/Common/CLP.h"

void F2LinearCode_test(const oc::CLP&);
void AltModWPrf_mod3BitDecompostion_test();
void AltModWPrf_sampleMod3_test(const oc::CLP& cmd);

void AltModWPrf_AMult_test(const oc::CLP& cmd);
void AltModWPrf_BMult_test(const oc::CLP& cmd);
void AltModWPrf_correction_test(const oc::CLP& cmd);
void AltModWPrf_convertToF3_test(const oc::CLP& cmd);
void AltModWPrf_keyMult_test(const oc::CLP& cmd);
void AltModWPrf_keyMultF3_test(const oc::CLP& cmd);

void AltModWPrf_mod2Ole_test(const oc::CLP& cmd);
void AltModWPrf_mod2OtF4_test(const oc::CLP& cmd);

void AltModWPrf_mod3_test(const oc::CLP& cmd);
void AltModWPrf_plain_test();
void AltModWPrf_proto_test(const oc::CLP& cmd);
void AltModWPrf_sharedKey_test(const oc::CLP& cmd);
void AltModWPrf_shared_test(const oc::CLP& cmd);

