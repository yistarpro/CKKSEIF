#ifndef CKKSEIF_ALGORITHMS_H
#define CKKSEIF_ALGORITHMS_H

// Umbrella header for the core library (libckkseif-core).
// Splits its contents into:
//   - eif.h:        Encrypted EEF Function + parameter selection + alternatives
//   - arithmetic.h: Comparison/ESF, bootstrap helpers, RotSum, eval helpers, Po2 rotation keys
//
// Apps that need PrivTopk-specific symbols (RankSelect, RankVec, BlockTopk*, Merge,
// BootPacked, PrivTopk variants, NEXUS) must include those headers explicitly:
//   - modules/privtopk/include/ckkseif/privtopk/ranking.h
//   - modules/privtopk/include/ckkseif/privtopk/privtopk.h
//   - modules/privtopk/include/ckkseif/privtopk/boot_packed.h
// This separation is what keeps `modules/privtopk/` liftable for its eventual
// standalone release.

#include "eif.h"
#include "arithmetic.h"

#endif
