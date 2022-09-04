#ifndef WIN_CONSUMER_H
#define WIN_CONSUMER_H

#include "RecOnlyHost.h"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
//#include "../util/MFUTab.h"
//#include "../util/STLutils.h"

#include "Event.h"

//#include "WinParser.h"

using namespace std;

struct SubjInfo {
  //PId pid;
  PId ppid; // parent pid
  SubjInstId sid;
  SubjInfo(SubjInstId s, PId pp): ppid(pp), sid(s) {};
  ~SubjInfo(){};
};

/*struct ObjInfo {
  //string path;
  char type;
  ObjInstId oid;
  ObjInfo(char objtype, ObjInstId obj) : type(objtype), oid(obj) {};
  ~ObjInfo() {};
};*/

struct NetInfo {
  ObjInstId src;
  ObjInstId sink;
};



class WinConsumer: public RecOnlyHost {

public:

  WinConsumer(const char* fout,
            const vector<unsigned>& ipaddr,
            const vector<unsigned>& netaddr,
            const vector<unsigned>& netmasks,
            bool logOpen, bool auditReadWr,
            bool prtFiles, bool prtEP, bool sortByFreq);

  ~WinConsumer();
  void processEv(Event ev);
  void prtSum();

private:

  void createProcEv(Event ev);
  void endProcEv(Event ev);
  void createThreadEv(Event ev);
  void readWriteEv(Event ev, bool wr);
  void createFileEv(Event ev);
  void removeEv(Event ev);
  void renameEv(Event ev);
  void connectEv(Event ev);
  void sendRecvEv(Event ev, bool send);
  void loadImageEv(Event ev);
  void createRegEv(Event ev);
  void removeRegEv(Event ev);
  void readWriteRegEv(Event ev);
  void openCloseEv(Event ev, bool open);
  // void allocMemEv(Event ev); 

  SubjInstId findSubj(Event ev);
  ObjInstId findObj(Event ev); 
  ObjInstId findSock(Event ev, bool isSink);
   
  //string countReadable(long count, int w);
  //void prtLost(long x, const char* s);
  
  /*map<PId, SubjInfo*> subjMap;
  map<string, ObjInfo*> objMap;// store object by path (key)
  map<string, ObjInstId> objMap2;// store object by ObjID (key)
  map<boost::tuple<uint32_t, uint32_t, 
	                uint32_t, uint32_t>, NetInfo*> netMap;*/

  /*MFUTable<PId, SubjInfo*> subjMap(32000);
  MFUTable<string, ObjInfo*> objMap(128000);// store object by path (key)
  MFUTable<string, ObjInstId> objMap2(128000);// store object by ObjID (key)
  MFUTable<tuple<uint32_t, uint32_t,
	  uint32_t, uint32_t>, NetInfo*> netMap(128000);*/
  //map<boost::tuple<uint32_t, uint32_t, uint32_t, uint32_t>, NetInfo*> netMap;


  PrincipalId userp;
  PrincipalId rootp;
  ObjInstId obj;
  SubjInstId subj;
  bool logOpen_, auditReadWr_;
  bool prtFiles_, prtEP_, sortByFreq_;

};
#endif
