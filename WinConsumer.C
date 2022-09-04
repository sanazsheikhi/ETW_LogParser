
//#include "RecOnlyHost.h"
#include "WinConsumer.h"
#include <iomanip>
#include "../util/STLutils.h"
#include "../util/MFUTab.h"

using namespace std;


long nresolved, nunresolved, nfforced, nfmissing, nffound,
nunspecep, nnetlinkep, ninetep, ninet6ep, nlocalep, nerrorep,
nlostopens, nlostrms, nlostrenms, nunkrms, nlostfdpair, nlostrdwr,
nlostmmap, nlostexec, nlostclone, nsubj, nautosubj, nsucc, nSockets,
readwrev, opencloseev, createProcev, endProcev, createThreadev, createFileev, 
removeev, renameev, connectev, sendRecvev, loadImageev, createRegev;


/*MFUTable<PId, SubjInfo*> subjMap(32000);
MFUTable<string, ObjInfo*> objMap(128000);// store object by path (key)
MFUTable<string, ObjInstId> objMap2(128000);// store object by ObjID (key)
MFUTable<tuple<uint32_t, uint32_t,
         uint32_t, uint32_t>, NetInfo*> netMap(128000);*/


MFUTable<PId, SubjInfo*> subjMap(32000);
//MFUTable<StrId, ObjInfo*> objMap(128000);// store object by path (key)
MFUTable<StrId, ObjInstId> objMap(128000);// store object by path (key)
//MFUTable<StrId, ObjInstId> objMap2(128000);// store object by ObjID (key)
MFUTable<tuple<uint32_t, uint32_t,
         uint32_t, uint32_t>, NetInfo*> netMap(128000);



WinConsumer::
WinConsumer(const char* fout, 
            const vector<unsigned>& ipaddr,
	    const vector<unsigned>& netaddr, 
            const vector<unsigned>& netmasks,
            bool logOpen, bool auditReadWr,
            bool prtFiles, bool prtEP, bool sortByFreq): 
            RecOnlyHost(fout, ipaddr, netmasks, netaddr, 1000),
            logOpen_(logOpen), auditReadWr_(auditReadWr),
            prtFiles_(prtFiles), prtEP_(prtEP), sortByFreq_(sortByFreq) {

  //roh = RecOnlyHost(fout, ipaddr, netmasks, netaddr, 1000);
  userp = addLocalPrincipal(UId(1000), GId(1000), PASSWORD);
  rootp = addLocalPrincipal(UId(0), GId(0), PASSWORD);
}

WinConsumer::
~WinConsumer() {
    
  subjMap.removeAndDestroyAll();
  /*for (auto it = subjMap.begin(); it != subjMap.end(); it++)
     delete it->second;*/
  objMap.removeAndDestroyAll();
  /*for (auto it = objMap.begin(); it != objMap.end(); it++)
     delete it->second;*/
  netMap.removeAndDestroyAll();
}



string countReadable(long count, int w) {
    char ss[21];
    if (count / 1000000000 >= 1) sprintf(ss, "%.*f%s", w, count / 1000000000.0, "B");
    else if (count / 1000000 >= 1) sprintf(ss, "%.*f%s", w, count / 1000000.0, "M");
    else if (count / 1000 >= 1) sprintf(ss, "%.*f%s", w, count / 1000.0, "K");
    else sprintf(ss, "%ld", count);
    return string(ss);
}



template <class K, class V> void
prtMap(unordered_map<K, V> ht, bool sortByCount,
       std::function<const char*(K)> str,
       std::function<unsigned short(V)> count) {
    vector<pair<const char*, unsigned>> entries(ht.size());
    unsigned sz=0;
    for (auto kv: ht) {
      const char* s = str(get<0>(kv));
      if (s) entries[sz++] = pair(s, count(get<1>(kv)));
    }

    if (sortByCount)
      sort(&entries[0], &entries[sz],
           [](auto k1, auto k2) {
              return (get<1>(k1) > get<1>(k2) ||
                      (get<1>(k1)==get<1>(k2) &&
                       (strcmp(get<0>(k1),get<0>(k2)) < 0)));
           });
    else sort(&entries[0], &entries[sz],
              [](auto k1, auto k2){return (strcmp(get<0>(k1),get<0>(k2)) < 0);});

    for (auto kf: entries)
       cerr << setw(5) << countReadable(get<1>(kf), 1)
            << setw(0) << ": " << get<0>(kf) << endl;
    cerr << endl;
}


void prtLost(long x, const char* s) {
    static long ct;
    if (x > 0) {
        if (ct % 5 != 0) cerr << ", ";
        cerr << "lost " << s << "s: " << countReadable(x, 3);
        if (++ct % 5 == 0)
            cerr << endl;
    }
}




void WinConsumer::
prtSum() {
    std::function<const char* (StrId)> sf = [this](StrId s) {return this->str(s); };
    if (prtFiles_) {
        cerr << "******** Files with access counts ********\n";
        std::function<unsigned short(MFUData<ObjInstId, unsigned short>)>
            cf = [](MFUData<ObjInstId, unsigned short> md) {return md.count(); };
        prtMap(objMap.htab(), sortByFreq_, sf, cf);
    }
    /*if (prtEP_) {
        cerr << "******** Endpoints with access counts ********\n";
        std::function<unsigned short(MFUData<MFUVoid, unsigned>)>
            cf = [](MFUData<MFUVoid, unsigned> md) {return md.count(); };
        prtMap(netMap.htab(), sortByFreq_, sf, cf);
    }*/


    cerr << "Subjects total: " << countReadable(nsubj, 3) << ",   "
        << (100. * nautosubj) / nsubj << "% auto created (forks not observed)\n";
    cerr << "Filenames resolved: " << countReadable(nffound, 3) << ",    pre-existing: "
        << countReadable(nfforced, 3) /* << ", unresolved: "
        << countReadable(nfmissing, 3)*/ << endl;
    /*cerr << "FDs resolved: " << countReadable(nresolved, 3)
        << ", unresolved: " << countReadable(nunresolved, 3) << endl;*/
    cerr << "Total syscalls: " << countReadable(nsucc, 1) /*+ nfailed, 3)
        << ", failed (scrv < 0): " << countReadable(nfailed, 3)*/
        << ",   read/writes: " << countReadable(readwrev, 3)
        << ",   createProcev: " << countReadable(createProcev, 3)
	<< ",   endProcev: " << countReadable(endProcev, 3)
	<< ",   createThreadev: " << countReadable(createThreadev, 3) << endl
	<< ",   createFileev: " << countReadable(createFileev, 3)
	<< ",   removeev: " << countReadable(removeev, 3)
	<< ",   renameev: " << countReadable(renameev, 3)
	<< ",   connectev: " << countReadable(connectev, 3) << endl
	<< ",   sendRecvev: " << countReadable(sendRecvev, 3)
	<< ",   loadImageev: " << countReadable(loadImageev, 3)
	<< ",   createRegev: " << countReadable(createRegev, 3)     
        /* << ",   open/close: " << countReadable(opencloseev, 3)*/ << endl;
    cerr << "lostopens: " << countReadable(nlostopens, 3) << ",   lost removes: " << countReadable(nlostrms, 3)
        << ",   lost renames: " << countReadable(nlostrenms, 3) << ",   nlostclones: " << countReadable(nlostclone, 3)
        <<",   nlostexec: " << nlostexec << ",   lost readWrites: " << nlostrdwr << endl;
    /*prtLost(nlostopens, "open");
    prtLost(nlostrms, "rm");
    prtLost(nlostrenms, "renm");
    //prtLost(nlostfdpair, "fdpair");
    //prtLost(nlostmmap, "mmap");
    prtLost(nlostclone, "clone");
    prtLost(nlostrdwr, "readWrite");*/
    //prtLost(nlostexec, "exec");
    /*cerr << ", unknown rms: " << countReadable(nunkrms, 3) << endl;
    cerr << "Endpoints ipv4: " << countReadable(ninetep, 3)
        << ", ipv6: " << countReadable(ninet6ep, 3)
        << ", local: " << countReadable(nlocalep, 3)
        << ", netlink: " << countReadable(nnetlinkep, 3)
        << ", unspec: " << countReadable(nunspecep, 3)
        << ", unhandled: " << countReadable(nerrorep, 3) << endl;*/
   //cerr << "Network Sockets: " << countReadable(nSockets, 3) << endl;

   
}



SubjInstId WinConsumer::
findSubj(Event ev) {
  subj = nullsiid;
  SubjInfo *si = subjMap.lookupData(PId(ev.pid));
  if (si != NULL  && si->sid != nullsiid)
    return si->sid;
  /*auto it = subjMap.find(PId(ev.pid));
  if (it != subjMap.end())
    return it->second->sid;*/
    
  string cmd = (!ev.cmd.empty())? ev.cmd : 
	(!ev.pname.empty())? ev.pname : "nullCmd"; 
  string img = (!ev.image.empty())? ev.image : cmd;
  ObjInstId bin =  preExistingFile(create(img.c_str()), rootp, ev.ts,
		                   Permission(00600));
  SubjInfo *pi = subjMap.lookupData(PId(ev.ppid)); // parent
  if (!pi || pi->sid == nullsiid) 
  //it = subjMap.find(PId(ev.ppid));
  //if (it == subjMap.end()) 
    {
    subj = preExistingSubj(PId(ev.pid), userp, create(cmd.c_str()), PId(1), ev.ts);
    nautosubj++;
    nlostclone++;
    nlostexec++;
  }
  /*else if (it->second->sid == nullsiid) {
    subj = preExistingSubj(PId(ev.pid), userp, create(cmd.c_str()), PId(1), ev.ts);
    nautosubj++;
    nlostclone++;
    nlostexec++;
  }*/
  else {
    //subj = clone(it->second->sid, PId(ev.pid), 0, ev.ts);
    subj = clone(pi->sid, PId(ev.pid), 0, ev.ts);
    execve(subj, create(cmd.c_str()), bin, ev.ts);
    // TODO: Check if there is any SID information to use for Principal
    setuid(subj, userp, ev.ts);
  }
  si = new SubjInfo(subj, PId(ev.ppid)); 
  subjMap.update(PId(ev.pid), si);
  //subjMap[PId(ev.pid)] = si;
  nsubj++;
  return subj;
}

ObjInstId WinConsumer::
findObj(Event ev) {
  obj = nulloiid;
  string path = "", id = "";
  path = ev.FileName;
  id = ev.FileObject;
  if (!path.empty()) {
    obj  = objMap.lookupData(create(path.c_str())); 
    if (obj != nulloiid) {
      nffound++;
      return obj;
    }
  }
   
  /*obj = objMap2.lookupData(create(id.c_str()));
  if (obj != nulloiid) {
      nffound++;
      return obj;
  }*/

  /*auto it = objMap2.find(id);
  if (it != objMap2.end()) {
      nffound++;
      return it->second;
  }*/

  if (path.empty()) 
    path = "unknownObject";

  obj = preExistingFile(create(path.c_str()), 
		        rootp, ev.ts, Permission(00600));
  nfforced++;

  /*if (path.compare("unknownObject")) {
    ObjInfo *oi = new ObjInfo('c', obj);
    //oi->type = 'c'; // TODO: think about this. It can be any object
    //oi->oid = obj;
    objMap.update(create(path.c_str()), oi);
    //objMap[path] = oi;
  }
  if (!id.empty()) 
    objMap2.update(create(id.c_str()), obj);*/
  objMap.update(create(path.c_str()), obj);

  return obj;
}

ObjInstId WinConsumer::
findSock(Event ev, bool isSink) {
  NetInfo *ni;
  pair<ObjInstId, ObjInstId> r;
  tuple<uint32_t, uint32_t, uint32_t, uint32_t> key;
  if (ev.saddr == 0 || ev.daddr == 0) return nulloiid;
  key = make_tuple(ev.saddr, ev.sport, ev.daddr, ev.dport);

  ni = netMap.lookupData(key);
  /*auto it = netMap.find(key);
  if (it != netMap.end())
    ni = it->second;*/

  if (ni && isSink) return ni->sink;
  if (ni && !isSink) return ni->src;
  r = connect(ev.saddr, ev.sport, ev.daddr, ev.dport, ev.ts, 0);
  if (r.first == nulloiid || r.second == nulloiid)
    return nulloiid;
  ni->src = r.first;
  nSockets++;
  ni->sink = r.second;
  nSockets++;
  netMap.update(key, ni);
  //netMap[key] = ni;
  if (isSink) return ni->sink;
  else return ni->src;
}

void WinConsumer::
processEv(Event ev) {
  //cout << "Consumer::processE Start  type: " << ev.type << endl;
  switch(ev.type) {
  case 0:
  case 1:
    createProcEv(ev); break;
  case 2:
  case 3:
  case 4:
    endProcEv(ev); break;
  case 8:
  case 9:
   createThreadEv(ev); break;
  case 16:
    readWriteEv(ev, false); break;
  case 17:
    readWriteEv(ev, true); break;
  case 18:
  case 19:
    createFileEv(ev); break;
  case 21:
    renameEv(ev); break;
  case 22:
  case 23:
  case 24:
    removeEv(ev); break;
  case 27:
  case 73:
    openCloseEv(ev,false);; break;  
  case 30:
  case 31:
    loadImageEv(ev); break;
  case 35:
  case 38:
  case 44:
  case 47:
  case 75:
    openCloseEv(ev, true); break;
  case 36:
  case 39:
  case 45:
  //case 47: // To be decided with openClose()
    sendRecvEv(ev, true); break;
  case 37:
  case 40:
  case 46:
  case 49:
    sendRecvEv(ev, false); break;
  case 62:
  case 71:
  case 74:
  case 76:
    readWriteEv(ev, false); break;
  case 67:
  case 72:
    readWriteEv(ev, true); break;
  case 63:
  case 65:
  case 69:
    removeEv(ev); break;
  case 68:
    createRegEv(ev);
  case 70:
    createFileEv(ev); break;
 
  default: return;        
  }
  nsucc++;
  if (nsucc % 10000 == 0)
      cout << nsucc << " events processed" << endl;
  if (nsucc % 100000 == 0) {
    cout << nsucc << " events processed" << endl;
    prtSum();
    sleep(5);
  }
  //cout << "consumer processEv end" << endl;
}

void WinConsumer::
createProcEv(Event ev) {
  createProcev++;
  findSubj(ev); 
 // cout << "createProcEv" << endl;
}

void WinConsumer::
endProcEv(Event ev) {
  endProcev++;
  /*auto it = subjMap.find(PId(ev.pid));
  if (it == subjMap.end())
    return;
  if (it->second->sid == nullsiid)
    return;
  subj = it->second->sid;  */

  SubjInfo* si = subjMap.lookupData(PId(ev.pid));
  if (!si || si->sid == nullsiid)
      return;

  subj = si->sid;
  exit(subj, ev.ts);
  subjMap.remove(PId(ev.pid));
  
  //cout << "endProcEv" << endl;
}

void WinConsumer::
createThreadEv(Event ev) {
  /*No remote memory creation info is available
    So, we report inject just by remote thread
    for now*/
  createThreadev++;
  PId p1 = PId(ev.ppid);
  PId p2 = PId(ev.pid);
  if (p1.id() != p2.id()) {
    SubjInfo *s1 = subjMap.lookupData(p1);
    SubjInfo *s2 = subjMap.lookupData(p2);
    
  if (s1 == NULL  || s1->sid == nullsiid)
     return; 
  if(s2 == NULL ||  s2->sid == nullsiid)
     return;
    
  inject(s1->sid, s2->sid, ev.ts);

  /*auto it1 = subjMap.find(p1);
   auto it2 = subjMap.find(p2);
   if (it1 == subjMap.end() || it2 == subjMap.end())
     return;
   SubjInstId s1 = it1->second->sid;
   SubjInstId s2 = it2->second->sid;

   if (s1 != nullsiid  && s2 != nullsiid)
     inject(s1, s2, ev.ts);*/
  }
  //cout << "createThreadEv" << endl;
}

void WinConsumer::
readWriteEv(Event ev, bool wr) {
  readwrev++;
  subj = findSubj(ev);
  obj = findObj(ev);
  if (subj == nullsiid) { 
    nlostrdwr++;
    return; 
  }
  if (obj == nulloiid) {
    obj = findSock(ev, wr);
    if (obj == nulloiid) {
      nlostrdwr++;
      return;
    }
  }
  uint64_t size = ev.IOSize;
  (wr) ? write(subj, obj, size, ev.ts) : 
	 read(subj, obj, size, ev.ts);
 
}

void WinConsumer::
createFileEv(Event ev) {
  createFileev++;
  // Implementation is based on CreateDisposition flag
  if ((subj = findSubj(ev)) == nullsiid) return;
  //ObjInfo *oi;
  string id = ev.FileObject;
  string path = ev.FileName;
  string cd = ev.CreateDispostion;

  if (path.empty()) return;
  // Check if the file exists or not.
  /*obj = nulloiid;
  if (!path.empty()) {
    oi = objMap.lookupData(create(path.c_str()));
    if(oi == NULL || oi->oid == nulloiid)
       obj = objMap2.lookupData(create(id.c_str()));
    else 
       obj = oi->oid;
  }*/
  
  /*obj = nulloiid;
  if (!path.empty()) {
    auto it = objMap.find(path);
    if (it != objMap.end())
      obj = it->second->oid;
    if (obj == nulloiid) {
      auto it2 = objMap2.find(id);
      if (it2 != objMap2.end())
        obj = it2->second;
     }
   }*/
  
  obj = objMap.lookupData(create(path.c_str()));

  if (!cd.compare("OPEN_EXISTING") || 
      !cd.compare("TRUNCATE_EXISTING")) { // opens a an existing file, truncates it and sets the size to 0
      if (obj == nulloiid) {
          nlostopens++;
          return;
      }
      else {
        if (logOpen_) 
          open(subj, obj, 0, ev.ts);
        
       if (!auditReadWr_) {
         string access = ev.ShareAccess;
         if (strstr(access.c_str(),"Read"))
           read(subj, obj, 0, ev.ts);
         if (strstr(access.c_str(),"Write"))
           write(subj, obj, 0, ev.ts);   
       }
	return;
      }
  }
  /*if ((obj != nulloiid) && !cd.compare("CREATE_NEW")) 
    return;*/

  if (!cd.compare("CREATE_NEW") || !cd.compare("CREATE_ALWAYS")) {
    //if (path.empty()) return;
    obj = create(subj, FILE_, create(path.c_str()), 
	         Permission(00600), ev.ts);

    //oi = new ObjInfo('f', obj);
    //oi->type = 'f';
    //oi->oid = obj;
    objMap.update(create(path.c_str()), obj);
    //objMap[path] = oi;
    /*if (!id.empty())
        //objMap2[id] = obj;
      objMap2.update(create(id.c_str()), obj);*/
    
    if (!auditReadWr_)
       write(subj, obj, 0, ev.ts);

    //cout << "createFileEv" << endl;
  }

  //if ("OPEN_ALWAYS")  //TODO not a correct place as the previous on may not execute FN
}

void WinConsumer::
removeEv(Event ev) {
  removeev++;
  if ((subj = findSubj(ev)) == nullsiid) { 
    nlostrms++;
    return; 
  }
    if ((obj = findObj(ev)) == nulloiid) { 
      nlostrms++;
      return;
    }
  remove(subj, obj, ev.ts);
  nunkrms++;
  string nm = ev.FileName;
  string id = ev.FileObject;
  objMap.remove(create(nm.c_str()));
  //objMap2.remove(create(id.c_str()));
  //objMap.erase(ev.FileName);
  //objMap2.erase(ev.FileObject);

 // cout << "removeEv" << endl;
}


void WinConsumer::
renameEv(Event ev) {
  renameev++;
// Maybe renamePath event gives more info
// However, No data in my samples for renamePath yet
// Rename event only has the name of thesource file
// After that we get FileIO/FileDelete and FileIo/FileCreate events 
// related to this event. However, integrating this information is not 
// straight forward. So, we call rename() from host using the source name and 
// unknown destination. Later on FileIO/FileCreate will be issured and complete
// information.
// 
  subj = findSubj(ev);
  obj = findObj(ev);
  if (subj == nullsiid || 
      obj == nulloiid) {
      nlostrenms++;
      return;
  }
  rename(subj, obj, create("UnknownObj"), ev.ts);
  //We don't store the obj in the objjMap as the name is not related to new name
  //We wait for create obj event on that.
 }

void WinConsumer::
connectEv(Event ev) {
  connectev++;
  subj = findSubj(ev);
  obj = findSock(ev, false);
  if (subj == nullsiid) return;
  if (obj == nulloiid) {
    obj = findObj(ev);
    if (obj == nulloiid)
      return;
  }
  if (logOpen_)
    open(subj, obj, 0, ev.ts);
  //cout << "connectEv" << endl;
}


void WinConsumer::
sendRecvEv(Event ev, bool send) {
  sendRecvev++;
  readWriteEv(ev, send); 
  //cout << "sendRecvEv" << endl;
}

void WinConsumer::
loadImageEv(Event ev) {
  loadImageev++;
  if ((subj = findSubj(ev)) == nullsiid) return;
  if((obj = findObj(ev)) == nulloiid) return;
  loadlib(subj, obj, ev.ts);
  //cout << "loadImageEv" << endl;
}

void WinConsumer::
createRegEv(Event ev) {
  createRegev++;
  // Here we didn't used FileCreate()
  // as we don't have createDisposition flag
  //ObjInfo* oi;
  string id = ev.FileObject;
  string path = ev.FileName;
  if (path.empty()) return;
  obj = create(subj, FILE_, create(path.c_str()),
        Permission(00600), ev.ts);

  //oi = new ObjInfo('f', obj); // should the type be 'r' fore registry

  objMap.update(create(path.c_str()), obj);
  //objMap[path] = oi;
  /*if (!id.empty())
      //objMap2[id] = obj;
      objMap2.update(create(id.c_str()), obj);*/
}


void WinConsumer::
openCloseEv(Event ev, bool op) {
    opencloseev++;
  subj = findSubj(ev);
  obj = findObj(ev);
  //ObjInstId obj1;
  if (subj == nullsiid) {
    if (op)
       nlostopens++;
      return;
  }
  if (obj  == nulloiid) {
    //obj = findObj(ev);
    //if (obj1 == nulloiid) {
        if (op)
          nlostopens++;
        return;
    }
  if (logOpen_ && op)
    open(subj, obj, 0, ev.ts);
  
  if (!op)
    close(subj, obj, ev.ts);
}


