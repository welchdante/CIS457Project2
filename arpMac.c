#include <stdio.h>

// https://gcc.gnu.org/onlinedocs/gcc-3.4.3/cpp/Stringification.html
#define xstr(s) str(s)
#define str(s) #s

#define ARP_CACHE       "/proc/net/arp"
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)

// Format for fscanf()
#define ARP_LINE_FORMAT "%" xstr(1024) "s %*s %*s " \
                        "%" xstr(1024) "s %*s " \
                        "%" xstr(1024) "s"

int main() {

    FILE *arpCache = fopen(ARP_CACHE, "r");

    // Need to ignore first line
    char ipAddr[ARP_BUFFER_LEN], hwAddr[ARP_BUFFER_LEN], device[ARP_BUFFER_LEN];
    int count = 0;
    
    // https://www.geeksforgeeks.org/scanf-and-fscanf-in-c-simple-yet-poweful/
    while (fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, hwAddr, device) == 3) {
        printf("%03d: Mac Address of [%s] on [%s] is \"%s\"\n", count++, ipAddr, device, hwAddr);
    }
    fclose(arpCache);
    return 0;
}