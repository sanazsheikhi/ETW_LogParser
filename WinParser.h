#ifndef WIN_PARSER_H
#define WIN_PARSER_H

#include <vector>
#include "STLutils.h"
#include "cvector.h"
#include <asm/types.h>
//#include "RecOnlyHost.h"
#include "WinConsumer.h"
#include "Event.h"

using namespace std;

// Process/DCStart, Start, End, Terminate
// Thread/DCStart, End, Terminate
// FileIO/Read, Write, Delete, Create, Rename,RenamePath, FileDelete, 
// DeletePath, Create, FileCreate, SetInfo, QueryInfo
// Image/Load, DCStart,
// TCPIP(UPDIP)/RevIPV4, SendIPV4, ConnectIPV4

/*struct Event {
  int type;
  string ts;
  //Process
  //PId pid;
  //PId ppid;
  int pid;
  int ppid;
  string SID;
  string pname;
  string image;
  string cmd;
  //string UniqueProcessKey; // no use
  //Thread
  string tid;
  unsigned long long StackBase; 
  unsigned long long StackLimit;
  unsigned long long UserStackBase;
  unsigned long long UserStackLimit;
  unsigned long long Win32StartAddr;
  // FileIO
  string FileObject; // not unique
  string FileName;
  uint32_t IOSize;
  //Network
  uint32_t saddr;
  uint32_t daddr;
  uint32_t sport;
  uint32_t dport;
  //Registry
  string KeyHandle;
  string KeyName;
  };*/

class WinParser {
//void initParser(int fd);
//void initParser(WinConsumer *consumer);
public:
char *curbuf_;
char *buf_;
long index_write;
long index_read;
long index_buf;

WinParser();
//void initParser();
void initParser(WinConsumer* WConsumer);
void parseAudit(int fd);
//void parseLine(Event &event);
void parseLine();
//Event parseEvent();
void parseEvent();

private:
unordered_map<string, int> scnm_;
WinConsumer* consumer;

string get(string m);
uint32_t a2i(const char *s);
uint32_t lhex2i(const char *s);
long a2l(const char *s);
uint64_t lhex2l(const char *s);
uint32_t parseIPV4(string destIP);
void pipeRead(); 

};
#endif
