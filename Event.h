#ifndef EVENT_H
#define EVENT_H

#include <string>
using namespace std;

struct Event{
  int type;
  unsigned long ts;
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
  string ShareAccess;
  //const char* FileName;
  string CreateDispostion; //TNBD
  uint32_t IOSize;
  //Network
  uint32_t saddr;
  uint32_t daddr;
  uint32_t sport;
  uint32_t dport;
  //Registry
  string KeyHandle;
  string KeyName;
  };

#endif
