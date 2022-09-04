#define PROC PP
#include <windows.h>
#undef PROC
#include "WinParser.h"
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <cstring.h>
#include <assert.h>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <unordered_map>
#include "../util/STLutils.h"
#include "../util/MFUTab.h"
#include "cset.h"


#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>



//HANDLE fileHandle;
#define MAX_BUF 1024

#define BUFSIZE (1<<20)

#define type(scnm) ((scnm_.find(scnm) == scnm_.end())?-1:scnm_[scnm])
//WinConsumer *wc;

//char *curbuf_;
//char *buf_;


//unordered_map<string, int> scnm_;

WinParser::
WinParser() {
  
  curbuf_ = (char*)malloc(BUFSIZE);
  index_write = 0;
  index_read = 0;
}


uint32_t WinParser::
a2i(const char *s) {
  unsigned char c; uint32_t rv=0;
  int sign = (*s == '-');
  if (sign) s++;
  while ((c = *s++))
    rv = rv*10 + (c - '0');
  return sign ? -rv : rv;
}

uint32_t WinParser::
lhex2i(const char *s) {
   unsigned int rv;   
   stringstream ss;
   ss << std::hex << s;
   ss >> rv;
   return rv;
}

long WinParser::
a2l(const char *s) {
  unsigned char c; long rv=0;
  int sign = (*s == '-');
  if (sign) s++;
  while ((c = *s++))
    rv = rv*10 + (c - '0');
  return sign ? -rv : rv;
}


uint64_t WinParser::
lhex2l(const char *s) {
  unsigned char c; uint64_t rv=0;
  while ((c = *s++)) {
    c -= '0';
    rv = (rv << 4)+c;
    if (c > 9)
      rv -= ('a' - '9' - 1);
  }
  return rv;
}


uint32_t WinParser::
parseIPV4(string destIP) {
  uint32_t destAddr = 0;
  if (destIP.find(':') != string::npos) {
    for (int i = 0; i < 6; i++) {
      auto pos = destIP.find(':');
      destIP = destIP.substr(pos+1, string::npos);
    }
    for (int i =0; i < 2; i++) {
      auto pos = destIP.find(':');
      stringstream ss;
      ss << hex << destIP.substr(0,pos);
      unsigned int x;
      ss >> x;
      destAddr = (destAddr << 16) + x;
      destIP = destIP.substr(pos+1, string::npos);
    }
    return destAddr;
  }
  else {
    for(int i = 0; i < 4; ++i) {
      auto pos = destIP.find('.');
      if (pos != string::npos) {
        destAddr = (destAddr << 8) + stoi(destIP.substr(0, pos));
        destIP = destIP.substr(pos + 1, string::npos);
      }
    }
    return destAddr;
  }
}



normalize(string& path) {
    // Normalizing the objects' paths to have same format 
    // avoiding different instances for the same object.
    size_t pos;
    map<string, string> formats = {
      {"c:", "C:"},
      {"\\??\\C:", "C:"},
      {"\\systemroot", "C:"},
      {"\%systemroot\%", "C:"},
      {"\\users", "C:\\users"},
      {"\\windows", "C:\\windows"},
      {"\\device\\harddiskvolume1", "A:"},
      {"\\device\\harddiskvolume2", "C:"},
      {"\\device\\harddiskvolume4", "F:"},
      {"\\program files", "C:\\program files"}
    };
    transform(path.begin(), path.end(), path.begin(), ::tolower);
    for (auto it = formats.begin(); it != formats.end(); it++) {
        string s = it->first;
        if ((pos = path.find(s)) != string::npos) {
            path.replace(pos, s.length(), it->second);
            break;
        }
    }
    if (path.back() == '\\') path.pop_back(); // About clustered alarms in UI
    /*// Replacing long SID in object path with username
    for (auto it = princMap.begin(); it != princMap.end(); it++)
        if ((pos = path.find(it->second->SID)) != string::npos) {
            path.replace(pos, it->second->SID.size(), it->second->uname);
            break;
        }*/
}



// search for field "m" in the buf_ and return its value
string WinParser::
get(string m) {
  // TODO: Replace the block of code with find() and substr() 
    if (!buf_) return "";
  char *t, *s, *e;
  if (!(t=strstr(buf_, m.c_str()))) return "";
  while(*t != '"' && *t != '\0') t++;
  if (*t == '"') s = ++t;
  else return "";
  while(*t != '"' && *t != '\0') t++;
  if (*t == '"') e = --t;
  else return "";
  size_t size = e-s+1;
  if (size <= 0) return "";
  char str[size+1];
  memmove(str,s,size);
  str[size] = '\0';
  return str;
}

//Event WinParser::
void WinParser::
parseEvent() {
  // TODO: This funcion should be edited
  // We can just get all the fields without chacking type
  // instead checking type in consummer for calling host functions
  
   Event ev;
  // If there exist no such fileds. It returns ""
  ev.ts = a2l(get("MSec=").c_str());
  ev.type = type(get("EventName"));
  //ev.pid = PId(a2i(get("PID=").c_str()));
  ev.pid = a2i(get("PID=").c_str());
  ev.pname = get("PName=");
  ev.tid = get("TID=");  
  ev.FileObject = get("FileObject=");//not unique,assigned upon Obj creation
  /*string fn = get("FileName=");
  cout << "fn1 : " << fn << endl;
  normalize(fn);
  cout << "fn2 : " << fn << endl;
  ev.FileName = fn;*/
  ev.FileName = get("FileName=");


  switch(ev.type) {
  case 0:    //Process/Start
  case 1:    //Process/DCStart
    //ev.ppid = PId(a2i(get("ParentID=").c_str()));
    ev.ppid = a2i(get("ParentID=").c_str());
    ev.image = get("ImageFileName="); 
    ev.cmd = get("CommandLine=");
    break;
  case 8:    //Thread/Start
  case 9:    //Thread/DCStart
    //ev.ppid = PId(lhex2i(get("ParentProcessID=").c_str()));
    ev.ppid = lhex2i(get("ParentProcessID=").c_str());
    ev.StackBase = stoull(get("StackBase="));
    ev.StackLimit = stoull(get("StackLimit="));
    ev.UserStackBase = stoull(get("UserStackBase="));
    ev.UserStackLimit= stoull(get("UserStackLimit="));
    ev.Win32StartAddr = stoull(get("Win32StartAddr="));
    break;
  case 16:   //FileIO/Read
  case 17:   //FileIO/Write
    //ev->FileName = get("FileName=");
    ev.IOSize = a2i(get("IoSize=").c_str());
    break;
  case 18:   //FileIO/Create
    ev.ShareAccess = get("FileIO/Create=");
  case 35:   //TcpIp/ConnectIPV4 
  case 38:   //TcpIp/Connect
  case 36:   //TcpIp/SendIPV4
  case 39:   //TcpIp/Send
  case 37:   //TcpIp/RecvIPV4
  case 40:   //TcpIp/Recv
  case 44:   //UdpIp/ConnectIPV4
  case 45:   //UdpIp/SendIPV4
  case 46:   //UdpIp/RecvIPV4
  case 47:   //UdpIp/Connect
  case 48:   //UdpIp/Send
  case 49:   //UdpIp/Recv
    ev.saddr = parseIPV4(get("saddr="));
    ev.daddr = parseIPV4(get("daddr="));
    ev.sport = a2i(get("sport=").c_str());
    ev.dport = a2i(get("daddr=").c_str());
    break;
  case  63: //Registry/Delete
  case  65: //Registry/DeleteValue
  case  66: //Registry/EnumerateKey
  case  67: //Registry/SetInformation
  case  68: //Registry/Create
  case  69: //Registry/KCBDelete
  case  70: //Registry/KCBCreate
  case  71: //Registry/QuerySecurity
  case  72: //Registry/SetValue
  case  73: //Registry/Close
  case  74: //Registry/QueryValue
    //ev.KeyHandle = get("KeyHandle=");
    //ev.KeyName = get("KeyName=");
   ev.FileName = get("KeyName=");
   ev.FileObject = get("KeyHandle=");
    break;
  default: {/*cout << "other" << endl;*/ return; }
  }
  consumer->processEv(ev);
}

//void parseLine(char* &p) {   //tmp snz
void WinParser::
parseLine() {
//parseLine(Event &ev) {
  char *t, end[2]={NULL};
  size_t size = 0;
  index_read = 0;
  size_t curbuf_size = strlen(curbuf_);
  t = curbuf_ + index_read;

  while (index_read < curbuf_size-1) {
    size = 0;
    memset(end, '\0', 2);
    t = curbuf_ + index_read;  


    while (*t != '\0' && *t != '>' && size <= curbuf_size) {
      t++;
      size++;
    }
    if (*t == '>')
        size++;

    
    if (buf_) {
        // To capture an incomplete event remained from previous pipe read
        char* tmp_buf = (char*)malloc(index_buf);
        memcpy(tmp_buf, buf_, index_buf);
        if (buf_)
          free(buf_);
        buf_ = NULL;
        buf_ = (char*)malloc(size+index_buf+1);
        memcpy(buf_, tmp_buf, index_buf);
        memcpy(buf_ + index_buf, curbuf_ + index_read, size);
        buf_[size + index_buf] = '\0';
        free(tmp_buf);
        tmp_buf = NULL;
        index_buf = 0;
    }
    else {
        buf_ = (char*)malloc(size+1);
        memcpy(buf_, curbuf_ + index_read, size); 
        buf_[size] = '\0';
    }

    index_read += size;

    memcpy(end, (buf_ + strlen(buf_)-2), 2);

     if(strstr(end, "/>") != NULL) {
        index_buf = 0;
        parseEvent();
        if (buf_) {
            free(buf_);
            buf_ = NULL;
        }
    }
    else {
        index_buf = size;
        return; // In the middle of a line
    }
  }
}

/*void WinParser::
parseAudit(int fd) {
  int nc=0, buflen=0;
  bool done=false;
  long remSpc;
  curbuf_ = (char*)malloc(BUFSIZE);
  while(!done) {
    char *p = curbuf_;
    remSpc = BUFSIZE-buflen;
    while (remSpc > 32) { // while buffer isn't close to full
      if ((done = (nc = read(fd, curbuf_+buflen, remSpc)) == 0))
        break; // No more data to read
      buflen += nc;
      remSpc -= nc; 
      parseLine(p);
    } 
    buflen = curbuf_ + buflen - p;
    char *tmpbuf_ = (char*)malloc(buflen+1);
    memmove(tmpbuf_, p , buflen);
    memset(curbuf_,'\0',BUFSIZE);
    memmove(curbuf_,tmpbuf_,buflen);
    free(tmpbuf_);
  }
  free(curbuf_);
}*/


void WinParser::
pipeRead() {

    char* pipename = "\\\\.\\pipe\\mypipe";
    HANDLE hPipe;
    DWORD Err;
    //while (1)
    //{
        hPipe = CreateFile(
            pipename,// pipe name
            GENERIC_READ | // read and write access
            GENERIC_WRITE,
            1, // no sharing
            NULL, // default security attributes
            OPEN_EXISTING, // opens existing pipe
            0, // default attributes
            NULL); // no template file

            // Break if the pipe handle is valid.

        Err = GetLastError();
        if (Err != 0) {
            if (hPipe == INVALID_HANDLE_VALUE) {
                printf("Could not open pipe. INVALID_HANDLE_VALUE.\n");
                if (Err == ERROR_ACCESS_DENIED)
                    printf("Access denied. Run as administrator\n");
            }
            else if (Err == ERROR_PIPE_BUSY) {
                printf("ERROR_PIPE_BUSY. Error code %d\n", Err);
                printf("Waiting for 30 seconds");
                if (!WaitNamedPipe(pipename, 30000)) {
                    printf("Could not open pipe: 30 second wait timed out.\n");
                    exit(-1);
                }
            }
            else
                printf("Could not open pipe. Error code %d\n", Err);

            exit(-1);
        }


        DWORD dwMode = PIPE_READMODE_MESSAGE;
        BOOL fSuccess = SetNamedPipeHandleState(
            hPipe, // pipe handle
            &dwMode, // new pipe mode
            NULL, // don't set maximum bytes
            NULL); // don't set maximum time

        if (!fSuccess) {
            printf("SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
            exit(-1);
        }

//#define BSIZE 10240
        TCHAR chBuf[BUFSIZE-1];
        //char chBuf[BUFSIZE]; //tmp snz
        DWORD cbRead;
        do {
           // Read from the pipe.
            cbRead = 0;
            memset(chBuf,NULL,BUFSIZE);
            //cout << "Reading from pipe ..." << endl;
            fSuccess = ReadFile(
                hPipe, // pipe handle
                chBuf, // buffer to receive reply
                (BUFSIZE-1) * sizeof(TCHAR), // size of buffer
                &cbRead, // number of bytes read
                NULL); // not overlapped

            if (!fSuccess && GetLastError() != ERROR_MORE_DATA) {
                printf("Reading from PIPE Stopped.\n\n"); // Error code %d ", GetLastError());
                //exit(-1);
                break;
            }


            memset(curbuf_, '\0', BUFSIZE);
            memcpy(curbuf_, chBuf, cbRead);
            //cout << "Processing events ..." << endl;
           parseLine();
        } while (1); //(GetLastError() == ERROR_MORE_DATA);//while (!fSuccess);
    //}
}



//void initParser(int fd) {
void WinParser::
initParser(WinConsumer *WConsumer) {
//initParser() {
  consumer = WConsumer;
  scnm_["Process/Start"] = 0;
  scnm_["Process/DCStart"] = 1 ;
  scnm_["Process/End"] = 2;
  scnm_["Process/DCEnd"] = 3;
  scnm_["Process/Terminate"] = 4;
  scnm_[""] = 5;
  scnm_[""] = 6;
  scnm_[""] = 7;
  scnm_["Thread/Start"] = 8;
  scnm_["Thread/DCStart"] = 9;
  scnm_["Thread/End"] = 10;
  scnm_["Thread/DCEnd"] = 11;
  scnm_["Thread/Terminate"] = 12;
  scnm_[""] = 13;
  scnm_[""] = 14;
  scnm_[""] = 15;
  scnm_["FileIO/Read"] = 16;
  scnm_["FileIO/Write"] = 17;
  scnm_["FileIO/FileCreate"] = 18;
  scnm_["FileIO/Create"] = 19;
  scnm_["FileIO/Rename"] = 20;
  scnm_["FileIO/RenamePath"] = 21;
  scnm_["FileIO/FileDelete"] = 22;
  scnm_["FileIO/Delete"] = 23;
  scnm_["FileIO/DeletePath"] = 24;
  scnm_["FileIo/SetInfo"] = 25;
  scnm_["FileIO/QueryInfo"] = 26;
  scnm_["FileIO/Close"] = 27;
  scnm_[""] = 28;
  scnm_[""] = 29;
  scnm_["Image/DCStart"] = 30;
  scnm_["Image/Load"] = 31;
  scnm_[""] = 32;
  scnm_[""] = 33;
  scnm_[""] = 34;
  scnm_["TcpIp/ConnectIPV4"] = 35;
  scnm_["TcpIp/SendIPV4"] = 36;
  scnm_["TcpIp/RecvIPV4"] = 37;
  scnm_["TcpIp/Connect"] = 38;
  scnm_["TcpIp/Send"] = 39;
  scnm_["TcpIp/Recv"] = 40;
  scnm_[""] = 41;
  scnm_[""] = 42;
  scnm_[""] = 43;
  scnm_["UdpIp/ConnectIPV4"] = 44;
  scnm_["UdpIp/SendIPV4"] = 45;
  scnm_["UdpIp/RecvIPV4"] = 46;
  scnm_["UdpIp/Connect"] = 47;
  scnm_["UdpIp/Send"] = 48;
  scnm_["UdpIp/Recv"] = 49;
  scnm_[""] = 50;
  scnm_[""] = 51;
  scnm_[""] = 52;
  scnm_["PageFault/VirtualAlloc"] = 53;
  scnm_["Memory/VirtualAllocDCStart"] = 54;
  scnm_[""] = 55;
  scnm_[""] = 56;
  scnm_[""] = 57;
  scnm_[""] = 58;
  scnm_[""] = 59;
  scnm_[""] = 60;
  scnm_["Registry/Config"] = 61;
  scnm_["Registry/QueryMultipleValue"] = 62;
  scnm_["Registry/Delete"] = 63;
  scnm_["Registry/EnumerateValueKey"] = 64;
  scnm_["Registry/DeleteValue"] = 65;
  scnm_["Registry/EnumerateKey"] = 66;
  scnm_["Registry/SetInformation"] = 67;
  scnm_["Registry/Create"] = 68;
  scnm_["Registry/KCBDelete"] = 69;
  scnm_["Registry/KCBCreate"] = 70;
  scnm_["Registry/QuerySecurity"] = 71;
  scnm_["Registry/SetValue"] = 72;
  scnm_["Registry/Close"] = 73;
  scnm_["Registry/QueryValue"] = 74;
  scnm_["Registry/Open"] = 75;
  scnm_["Registry/Query"] = 76;
  scnm_[""] = 77;
  scnm_[""] = 78;

  pipeRead();
  //parseAudit(fd);
  
}
