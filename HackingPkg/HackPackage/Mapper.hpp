#include "nt_helper.hpp"

namespace Mapper{
    void*& LoadEvilSys();
    void MapEvilSys(PKLDR_DATA_TABLE_ENTRY Ntoskrnl, PKLDR_DATA_TABLE_ENTRY TargetModule);
}