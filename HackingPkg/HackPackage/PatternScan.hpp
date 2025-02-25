
template<typename T>
T PatternScan(unsigned char* begin, unsigned char* end, const char* pattern, unsigned long size){
    for(unsigned char* crnt = begin; crnt != end - size; ++crnt){
        bool found = true;
        for(unsigned long i = 0; i < size; ++i){
            if(pattern[i] == '?') continue;
            if(crnt[i] != *(unsigned char*)(pattern + i))
            {
                found = false;
                break;
            }
        }
        if(found){
            return (T)crnt;
        }
    }
    return (T)nullptr;
}