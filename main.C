//#include "LinuxParser.h"
//#include "AuditConsumer.h"
#include "WinParser.h"
#include "WinConsumer.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <signal.h>
bool dbg = 0;
long insct;

WinConsumer* consumer;

void prtUsage(int argc, char* argv[]) {
   cerr << "Usage: " << argv[0] << " [-a] [-c] {-i myIPaddress}+ [-l logLevel]"
        << " {-n networkAddr/netMask}+ [-o] [-pf] [-ps] [-r] [-w width]"
        << " <auditFile> <recordFile>\n"
        << "    -a:  append last 3 digits of audit sequence # to timestamp\n"
        << "    -c:  sort these lists by access count (default: alphabetic)\n"
        << "    -l logLevel: specify logging level, defaults to "<<ERRLEVEL<<endl
        << "    -o: record opens in the record file\n"
        << "    -pf: print the list of files accessed\n"
        << "    -ps: print the list of sockets accessed\n"
        << "    -r: audit file contains reads and writes\n"
        << "    -w width: format output for display with width columns\n";
   exit(1);
}

int logLevel=0;//WARNLEVEL;
bool appendSeqToTs;
int main(int argc, char* argv[]) {
   bool auditRdWr=false, logOpen=false, summarizeFiles=false, summarizeEP=true;
   bool sortByFreq=false;
   int width=80;
   const char* inf=nullptr, *outf=nullptr;
   vector<unsigned> ipaddrs, netmasks, netaddrs;

   for (int i=1; i < argc; i++) {
      if (argv[i][0] == '-') {
         switch (argv[i][1]) {
         case 'a': appendSeqToTs=true; break;

         case 'c': sortByFreq=true; break;

         case 'i': {
            unsigned r1, r2, r3, r4;
            if (++i >= argc ||
                 (sscanf(argv[i], "%d.%d.%d.%d", &r1, &r2, &r3, &r4) < 4))
                prtUsage(argc, argv);
            ipaddrs.push_back((r1<<24)+(r2<<16)+(r3<<8)+r4);
            break;
         }

         case 'l':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &logLevel) < 1))
               prtUsage(argc, argv);
            break;

         case 'n': {
            unsigned r1, r2, r3, r4, r5, r6, r7, r8;
            if (++i >= argc ||
                (sscanf(argv[i], "%d.%d.%d.%d/%d.%d.%d.%d", &r1, &r2, &r3, &r4,
                   &r5, &r6, &r7, &r8) < 8))
               prtUsage(argc, argv);
            netaddrs.push_back((r1<<24)+(r2<<16)+(r3<<8)+r4);
            netmasks.push_back((r5<<24)+(r6<<16)+(r7<<8)+r8);
            break;
         }

         case 'o': logOpen = true; break;

         case 'p': 
            if (argv[i][2] == 'f') 
               summarizeFiles = true;
            else if (argv[i][2] == 's')
               summarizeEP = true;
            else prtUsage(argc, argv);
            break;

         case 'r': auditRdWr = true; break;

         case 'w':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &width) < 1))
               prtUsage(argc, argv);
            break;

         default: prtUsage(argc, argv); break;
         }
      }
      /*else if (inf == nullptr)
         inf = argv[i];*/
      else if (outf == nullptr) 
         outf = argv[i];
      else prtUsage(argc, argv);
   }

   /*if (!inf)
      prtUsage(argc, argv);*/

   /*int infd = -1; char cmd[strlen(inf) + 64] = "";
   if (strstr(inf, ".gz") && strcmp(strstr(inf, ".gz"), ".gz") == 0)
      sprintf(cmd, "zcat %s", inf);
   else if (strstr(inf, ".gzt") && strcmp(strstr(inf, ".gzt"), ".gzt") == 0)
      sprintf(cmd, "tail -c +0 -f %s|gzip -cd", inf);
   else if (strstr(inf, ".t") && strcmp(strstr(inf, ".t"), ".t") == 0)
      sprintf(cmd, "tail -c +0 -f %s", inf);
   else if ((infd = open(inf, O_RDONLY)) < 0) {
      int i;
      if (infd < 0 && (sscanf(inf, "fd:%d", &i) == 1))
         infd = i;
      else {
         cerr << "Unable to read audit file, exiting\n";
         exit(1);
      }
   }

   if (infd < 0) {
      int pid; int p[2];
      if (pipe(p) >= 0) {
         if ((pid = vfork()) == 0) {
            dup2(p[1], 1);
            close(p[0]);
            execl("/bin/sh", "sh", "-c", cmd, NULL);
         }
         else if (pid > 0) {
            close(p[1]);
            infd = p[0];
         }
         else { cerr << "Unexpected error in fork, exiting\n"; exit(1); }
      }
   }

   if (fcntl(infd, F_GETFD) < 0) {
      cerr << infd << " is not a valid file descriptor, exiting\n";
      exit(1);
   }*/

   if (outf)
      consumer = 
        new WinConsumer(outf, ipaddrs, netmasks, netaddrs, logOpen, auditRdWr,
                          summarizeFiles, summarizeEP, sortByFreq);
   WinParser *parser = new WinParser();
   parser->initParser(consumer);

   if (consumer) {
      consumer->prtSum();
      delete consumer;
   }
   //prtSum(width);
   //return rv;
   return 0;
}
