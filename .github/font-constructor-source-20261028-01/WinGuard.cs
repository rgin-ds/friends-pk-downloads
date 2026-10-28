// TEST ONLY. One private constructor diagnostic; no force termination API exists in this source.
using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public static class FontWinGuard {
    public static void Need(bool ok,string code){if(!ok)throw new InvalidOperationException(code);}
    const uint READ=0x80000000,WRITE=0x40000000,READ_CONTROL=0x20000,WRITE_DAC=0x40000;
    const uint OPEN=3,NEW=1,REPARSE=0x00200000,BACKUP=0x02000000,DIR=0x10,RP=0x400;
    const uint SHARE_READ=1,SHARE_WRITE=2,ALL=0x1f01ff;
    public static string Sid=WindowsIdentity.GetCurrent().User.Value;
    public static DateTime DeadlineUtc=DateTime.UtcNow.AddSeconds(480);
    static void Budget(){Need(DateTime.UtcNow<DeadlineUtc,"ABSOLUTE_IO_DEADLINE");}
    public static string Hex(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
    static void Win(bool ok,string code){Need(ok,code);}
    [StructLayout(LayoutKind.Sequential)] struct SA {public int length;public IntPtr descriptor;public int inherit;}
    [StructLayout(LayoutKind.Sequential)] struct FT {public uint low,high;public long Value {get{return ((long)high<<32)|low;}}}
    [StructLayout(LayoutKind.Sequential)] struct FI {public uint attrs;public FT creation,access,write;public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;}
    [StructLayout(LayoutKind.Sequential)] struct BASIC {public long creation,access,write,change;public uint attrs;}
    [StructLayout(LayoutKind.Sequential)] struct TAG {public uint attrs,tag;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,ref SA sa,uint d,uint f,IntPtr t);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string p,ref SA sa);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out FI i);
    [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")] static extern bool BasicInfo(SafeFileHandle h,int c,out BASIC i,uint n);
    [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")] static extern bool TagInfo(SafeFileHandle h,int c,out TAG i,uint n);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder s,uint n,uint f);
    [DllImport("kernel32.dll")] static extern uint GetFileType(SafeFileHandle h);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool GetVolumeInformationW(string p,StringBuilder a,uint n,out uint serial,out uint max,out uint flags,StringBuilder fs,uint cap);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s,uint r,out IntPtr p,out uint n);
    [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr sd);
    [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(SafeFileHandle h,int type,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr sd);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    static SA Security(bool directory){
        string flags=directory?"OICI":"";IntPtr p;uint n;
        Win(ConvertStringSecurityDescriptorToSecurityDescriptorW("O:"+Sid+"D:P(A;"+flags+";FA;;;"+Sid+")(A;"+flags+";FA;;;SY)",1,out p,out n),"SD_CREATE");
        return new SA{length=Marshal.SizeOf(typeof(SA)),descriptor=p,inherit=0};
    }
    public static string Canon(string p){
        Need(!String.IsNullOrEmpty(p)&&p.Length<240&&p.Length>=3&&Char.IsLetter(p[0])&&p[1]==':'&&p[2]=='\\',"LOCAL_PATH");
        Need(p.IndexOf(':',2)<0&&p.IndexOf('/')<0&&p.IndexOf('\0')<0,"PATH_FORM");
        string full=Path.GetFullPath(p).TrimEnd('\\');Need(String.Equals(full,p.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase),"CANON_PATH");return full;
    }
    public static void Leaf(string name){Need(!String.IsNullOrEmpty(name)&&name!="."&&name!=".."&&name.Length<=100
        &&name.IndexOfAny(new[]{'\\','/',':','\0'})<0&&!name.EndsWith(".")&&!name.EndsWith(" "),"FIXED_LEAF");}
    static SafeFileHandle Open(string p,bool dir,uint access,uint share){SA sa=new SA{length=Marshal.SizeOf(typeof(SA))};
        var h=CreateFileW(p,access,share,ref sa,OPEN,REPARSE|(dir?BACKUP:0),IntPtr.Zero);Need(!h.IsInvalid,"OPEN_NOFOLLOW");return h;}
    static string Final(SafeFileHandle h){var s=new StringBuilder(512);uint n=GetFinalPathNameByHandleW(h,s,512,0);Need(n>0&&n<512,"FINAL_PATH");string p=s.ToString();Need(p.StartsWith("\\\\?\\")&&!p.StartsWith("\\\\?\\UNC\\"),"FINAL_LOCAL");return Canon(p.Substring(4));}
    public sealed class Stamp {
        public string path,id,sha256;public long bytes,creation,write,change;public uint links;public bool directory;
        public bool Same(Stamp b){return b!=null&&id==b.id&&bytes==b.bytes&&creation==b.creation&&write==b.write&&change==b.change&&links==b.links&&directory==b.directory&&path==b.path&&sha256==b.sha256;}
    }
    static Stamp Meta(SafeFileHandle h,string path,bool directory){
        Budget();FI i;BASIC b;TAG t;Win(GetFileInformationByHandle(h,out i),"FILE_INFO");Win(BasicInfo(h,0,out b,(uint)Marshal.SizeOf(typeof(BASIC))),"BASIC_INFO");Win(TagInfo(h,9,out t,(uint)Marshal.SizeOf(typeof(TAG))),"TAG_INFO");
        Need(GetFileType(h)==1&&(i.attrs&(RP|0x40))==0&&t.tag==0&&(t.attrs&RP)==0&&((i.attrs&DIR)!=0)==directory,"REGULAR_NO_REPARSE");
        Need(String.Equals(Final(h),Canon(path),StringComparison.OrdinalIgnoreCase),"HANDLE_PATH");if(!directory)Need(i.links==1,"SINGLE_LINK");
        return new Stamp{path=Canon(path).ToLowerInvariant(),id=i.volume.ToString("x8")+":"+i.indexHigh.ToString("x8")+i.indexLow.ToString("x8"),bytes=((long)i.sizeHigh<<32)|i.sizeLow,
            creation=b.creation,write=b.write,change=b.change,links=i.links,directory=directory};
    }
    static RawSecurityDescriptor Descriptor(SafeFileHandle h){IntPtr o,g,d,s,p;Need(GetSecurityInfo(h,1,5,out o,out g,out d,out s,out p)==0,"SECURITY_INFO");
        try{uint n=GetSecurityDescriptorLength(p);Need(n>0&&n<=8192,"SD_SIZE");byte[] b=new byte[n];Marshal.Copy(p,b,0,(int)n);return new RawSecurityDescriptor(b,0);}finally{LocalFree(p);}}
    static void Acl(SafeFileHandle h,bool directory,bool inheritedAllowed){
        AclDescriptor(Descriptor(h),directory,inheritedAllowed);
    }
    static void AclDescriptor(RawSecurityDescriptor d,bool directory,bool inheritedAllowed){
        Need(d.Owner!=null&&d.Owner.Value==Sid&&d.DiscretionaryAcl!=null&&d.DiscretionaryAcl.Count==2,"OWNER_DACL");
        if(!inheritedAllowed)Need((d.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0,"DACL_PROTECTED");
        var got=new HashSet<string>();foreach(GenericAce a in d.DiscretionaryAcl){var c=a as CommonAce;Need(c!=null&&c.AceQualifier==AceQualifier.AccessAllowed&&!c.IsCallback&&(uint)c.AccessMask==ALL,"EXACT_FULLCONTROL");
            uint allowed=(directory?3u:0u)|(inheritedAllowed?16u:0u);Need(((uint)c.AceFlags&~allowed)==0,"ACE_FLAGS");Need(c.SecurityIdentifier.Value==Sid||c.SecurityIdentifier.Value=="S-1-5-18","ALLOWED_SID");Need(got.Add(c.SecurityIdentifier.Value),"DUPLICATE_ACE");}
        Need(got.Count==2&&got.Contains(Sid)&&got.Contains("S-1-5-18"),"EXACT_SIDS");
    }
    static List<SafeFileHandle> Parents(string p){
        p=Canon(p);string root=Path.GetPathRoot(p);uint serial,max,flags;var fs=new StringBuilder(32);Need(GetVolumeInformationW(root,null,0,out serial,out max,out flags,fs,32)&&fs.ToString()=="NTFS","LOCAL_NTFS");
        var hs=new List<SafeFileHandle>();try{string cur=root;string rest=Path.GetDirectoryName(p).Substring(root.Length);foreach(string bit in rest.Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries)){
            Leaf(bit);cur=Path.Combine(cur,bit);var h=Open(cur,true,0x80|READ_CONTROL,SHARE_READ|SHARE_WRITE);hs.Add(h);Meta(h,cur,true);
        }return hs;}catch{foreach(var h in hs)h.Dispose();throw;}
    }
    public static Stamp AuditDirectory(string p){var parents=Parents(p);try{using(var h=Open(Canon(p),true,0x80|READ_CONTROL,SHARE_READ|SHARE_WRITE)){var m=Meta(h,p,true);Acl(h,true,false);return m;}}finally{foreach(var h in parents)h.Dispose();}}
    public static byte[] Read(string p,int cap,out Stamp stamp){
        Budget();
        var parents=Parents(p);try{using(var h=Open(Canon(p),false,READ|READ_CONTROL,SHARE_READ)){
            var before=Meta(h,p,false);Acl(h,false,false);Need(before.bytes>=0&&before.bytes<=cap,"READ_CAP");byte[] data=new byte[(int)before.bytes];
            using(var stream=new FileStream(h,FileAccess.Read,4096,false)){int at=0,n;while(at<data.Length){Budget();n=stream.Read(data,at,data.Length-at);Need(n>0,"WHOLE_READ");at+=n;}Need(stream.ReadByte()==-1,"NO_TRAILING");
                var after=Meta(h,p,false);Need(before.Same(after),"FD_CHANGED");before.sha256=Hex(data);stamp=before;
                using(var path=Open(p,false,0x80|READ_CONTROL,SHARE_READ)){Need(Meta(path,p,false).id==before.id,"PATH_REPLACED");Acl(path,false,false);}Budget();return data;
            }
        }}finally{foreach(var h in parents)h.Dispose();}
    }
    public static void Mkdir(string p){p=Canon(p);var parents=Parents(p);SA sa=Security(true);try{Win(CreateDirectoryW(p,ref sa),"EXCLUSIVE_DIRECTORY");AuditDirectory(p);}finally{LocalFree(sa.descriptor);foreach(var h in parents)h.Dispose();}}
    public static void WriteNew(string p,byte[] bytes){var parents=Parents(p);SA sa=Security(false);try{using(var h=CreateFileW(Canon(p),WRITE|READ_CONTROL,0,ref sa,NEW,REPARSE,IntPtr.Zero)){
        Need(!h.IsInvalid,"EXCLUSIVE_FILE");using(var stream=new FileStream(h,FileAccess.Write)){stream.Write(bytes,0,bytes.Length);stream.Flush(true);} }
        Stamp stamp;byte[] actual=Read(p,bytes.Length,out stamp);Need(Hex(actual)==Hex(bytes),"WRITE_HASH");
    }finally{LocalFree(sa.descriptor);foreach(var h in parents)h.Dispose();}}
    // Only known newly-created Java output nodes: never repair an unknown or foreign ACL/owner/path.
    public static void ProtectOutput(string p,bool dir){var parents=Parents(p);try{using(var h=Open(p,dir,READ_CONTROL|WRITE_DAC|0x80,SHARE_READ)){
        Meta(h,p,dir);Acl(h,dir,true);SA sa=Security(dir);try{var d=new RawSecurityDescriptor(MarshalBytes(sa.descriptor),0);byte[] raw=new byte[d.DiscretionaryAcl.BinaryLength];d.DiscretionaryAcl.GetBinaryForm(raw,0);IntPtr acl=Marshal.AllocHGlobal(raw.Length);
            try{Marshal.Copy(raw,0,acl,raw.Length);Need(SetSecurityInfo(h,1,0x80000004,IntPtr.Zero,IntPtr.Zero,acl,IntPtr.Zero)==0,"PROTECT_OUTPUT");}finally{Marshal.FreeHGlobal(acl);}
        }finally{LocalFree(sa.descriptor);}Acl(h,dir,false);
    }}finally{foreach(var h in parents)h.Dispose();}}
    static byte[] MarshalBytes(IntPtr p){int n=(int)GetSecurityDescriptorLength(p);byte[] b=new byte[n];Marshal.Copy(p,b,0,n);return b;}
    public static int PureControls(){
        int count=0;Action<bool> good=v=>{Need(v,"PURE_CONTROL");count++;};Action<Action> bad=attempt=>{bool refused=false;try{attempt();}catch(InvalidOperationException){refused=true;}good(refused);};
        Leaf("Client$Provider.class");good(true);
        foreach(string x in new[]{".","..","x/y","x\\y","file:stream","bad.","bad ",""})bad(()=>Leaf(x));
        good(Canon(@"C:\safe\file")==@"C:\safe\file");
        foreach(string x in new[]{@"\\host\share\x",@"relative",@"C:\x\..\file",@"C:\x\\file",@"C:\x:stream"})bad(()=>Canon(x));
        var a=new Stamp{id="one",path="x",sha256="aa",bytes=1,links=1};var b=new Stamp{id="one",path="x",sha256="aa",bytes=1,links=1};good(a.Same(b));b.sha256="bb";good(!a.Same(b));b.sha256="aa";b.id="two";good(!a.Same(b));
        string entries="(A;;FA;;;"+Sid+")(A;;FA;;;SY)";
        AclDescriptor(new RawSecurityDescriptor("O:"+Sid+"D:P"+entries),false,false);good(true);
        AclDescriptor(new RawSecurityDescriptor("O:"+Sid+"D:P(A;OICI;FA;;;"+Sid+")(A;OICI;FA;;;SY)"),true,false);good(true);
        bad(()=>AclDescriptor(new RawSecurityDescriptor("O:SYD:P"+entries),false,false));
        bad(()=>AclDescriptor(new RawSecurityDescriptor("O:"+Sid+"D:"+entries),false,false));
        bad(()=>AclDescriptor(new RawSecurityDescriptor("O:"+Sid+"D:P(A;;FA;;;WD)(A;;FA;;;SY)"),false,false));
        bad(()=>AclDescriptor(new RawSecurityDescriptor("O:"+Sid+"D:P(A;ID;FA;;;"+Sid+")(A;ID;FA;;;SY)"),false,false));
        Need(count==24,"PURE_COUNT");return count;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI {public uint cb;public string reserved,desktop,title;public uint x,y,xs,ys,xc,yc,fill,flags;public ushort show,reserved2;public IntPtr reserved3,input,output,error;}
    [StructLayout(LayoutKind.Sequential)] struct SIX {public SI startup;public IntPtr attributes;}
    [StructLayout(LayoutKind.Sequential)] struct PI {public IntPtr process,thread;public uint pid,tid;}
    [StructLayout(LayoutKind.Sequential)] struct LIMIT {public long processTime,jobTime;public uint flags;public UIntPtr minWorking,maxWorking;public uint activeProcesses;public UIntPtr affinity;public uint priority,scheduling;}
    [StructLayout(LayoutKind.Sequential)] struct IO {public ulong r,w,o,rb,wb,ob;}
    [StructLayout(LayoutKind.Sequential)] struct EXT {public LIMIT basic;public IO io;public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;}
    [StructLayout(LayoutKind.Sequential)] struct ACCOUNT {public long user,kernel,periodUser,periodKernel;public uint faults,total,active,terminated;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SIX startup,out PI info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SA sa,uint size);
    [DllImport("kernel32.dll")] static extern bool SetHandleInformation(IntPtr h,uint mask,uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(ref SA sa,string name);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr OpenJobObjectW(uint access,bool inherit,string name);
    [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job,int type,ref EXT info,uint bytes);
    [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] static extern bool QueryInformationJobObject(IntPtr job,int type,out ACCOUNT info,uint bytes,IntPtr returned);
    [DllImport("kernel32.dll")] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool inside);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h,out uint code);
    [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h,out FT creation,out FT exit,out FT kernel,out FT user);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h,uint flags,StringBuilder name,ref uint size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr p,int count,uint flags,ref IntPtr bytes);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attr,IntPtr values,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr p);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll")] static extern bool FreeConsole();
    [DllImport("kernel32.dll")] static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll")] static extern bool SetConsoleCtrlHandler(IntPtr handler,bool add);
    [DllImport("kernel32.dll")] static extern bool GenerateConsoleCtrlEvent(uint signal,uint group);
    [DllImport("kernel32.dll")] static extern uint GetConsoleProcessList([Out] uint[] p,uint count);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    public sealed class Identity {public uint pid;public long creation;public string image,job;}
    public sealed class ProbeResult {public string status="UNKNOWN_OWNED_PROBE_CLOSURE";public Identity identity;public bool closed,jobEmpty,captureClosed,signalAttempted,helperClosed;public uint exitCode;public byte[] stdout,stderr;public bool captureExceeded;public string errorCode;}
    static string Image(IntPtr h){var b=new StringBuilder(512);uint n=512;Need(QueryFullProcessImageNameW(h,0,b,ref n)&&n>0&&n<512,"PROCESS_IMAGE");return Canon(b.ToString());}
    static long Created(IntPtr h){FT c,e,k,u;Need(GetProcessTimes(h,out c,out e,out k,out u),"PROCESS_TIMES");return c.Value;}
    static uint Active(IntPtr job){ACCOUNT a;Need(QueryInformationJobObject(job,1,out a,(uint)Marshal.SizeOf(typeof(ACCOUNT)),IntPtr.Zero),"JOB_ACCOUNTING");return a.active;}
    static string Quote(string s){Need(s.IndexOf('"')<0&&s.IndexOf('\0')<0&&!s.EndsWith("\\"),"FIXED_ARGV");return "\""+s+"\"";}
    sealed class Pump {
        public Thread thread;public byte[] bytes;public volatile bool exceeded;public Exception error;
        public Pump(IntPtr read){thread=new Thread(()=>{try{using(var stream=new FileStream(new SafeFileHandle(read,true),FileAccess.Read,4096,false))using(var data=new MemoryStream()){
            byte[] buffer=new byte[4096];int n;long total=0;while((n=stream.Read(buffer,0,buffer.Length))>0){total+=n;if(total>32768)exceeded=true;int keep=Math.Min(n,32768-(int)data.Length);if(keep>0)data.Write(buffer,0,keep);}bytes=data.ToArray();
        }}catch(Exception e){error=e;}});thread.IsBackground=true;thread.Name="owned-private-capture";thread.Start();}
    }
    public static ProbeResult Run(string java,string[] args,string cwd,Dictionary<string,string> environment,string nonce,Func<Identity,bool> graceful){
        var r=new ProbeResult();PI pi=new PI();IntPtr job=IntPtr.Zero,attr=IntPtr.Zero,handles=IntPtr.Zero,env=IntPtr.Zero,ow=IntPtr.Zero,ew=IntPtr.Zero,ir=IntPtr.Zero;Pump op=null,ep=null;bool attrs=false;
        try{
            Need(System.Text.RegularExpressions.Regex.IsMatch(nonce,"\\A[0-9a-f]{32}\\z"),"NONCE");java=Canon(java);cwd=Canon(cwd);Stamp exe;Read(java,49792,out exe);Need(exe.sha256=="9fcc7d5d43918e389df240d44601c98a4d3aa9e7d0cbbd6d208304e0b574c7e2","EXACT_JAVA");
            SA secure=Security(false);try{job=CreateJobObjectW(ref secure,"Local\\font-probe-"+nonce);Need(job!=IntPtr.Zero&&Marshal.GetLastWin32Error()!=183,"FRESH_JOB");}finally{LocalFree(secure.descriptor);}
            EXT limit=new EXT();limit.basic.flags=8|0x100;limit.basic.activeProcesses=1;limit.processMemory=(UIntPtr)(512u*1024u*1024u);
            Need(SetInformationJobObject(job,9,ref limit,(uint)Marshal.SizeOf(typeof(EXT))),"JOB_LIMITS"); // No KILL_ON_JOB_CLOSE.
            SA inheritable=new SA{length=Marshal.SizeOf(typeof(SA)),inherit=1};IntPtr or,er;
            Need(CreatePipe(out or,out ow,ref inheritable,4096)&&SetHandleInformation(or,1,0),"STDOUT_PIPE");op=new Pump(or);
            Need(CreatePipe(out er,out ew,ref inheritable,4096)&&SetHandleInformation(er,1,0),"STDERR_PIPE");ep=new Pump(er);
            using(var nul=CreateFileW("NUL",READ,SHARE_READ|SHARE_WRITE,ref inheritable,OPEN,0,IntPtr.Zero)){
                Need(!nul.IsInvalid,"STDIN_NUL");ir=nul.DangerousGetHandle();IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);Need(size.ToInt64()>0&&size.ToInt64()<65536,"ATTRIBUTE_SIZE");attr=Marshal.AllocHGlobal(size);
                Need(InitializeProcThreadAttributeList(attr,1,0,ref size),"ATTRIBUTES");attrs=true;handles=Marshal.AllocHGlobal(3*IntPtr.Size);Marshal.WriteIntPtr(handles,0,ir);Marshal.WriteIntPtr(handles,IntPtr.Size,ow);Marshal.WriteIntPtr(handles,2*IntPtr.Size,ew);
                Need(UpdateProcThreadAttribute(attr,0,(IntPtr)0x20002,handles,(IntPtr)(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"ONLY_STD_HANDLE_INHERITANCE");
                string eb=String.Join("\0",environment.OrderBy(p=>p.Key,StringComparer.OrdinalIgnoreCase).Select(p=>p.Key+"="+p.Value))+"\0\0";env=Marshal.StringToHGlobalUni(eb);
                SIX si=new SIX();si.startup.cb=(uint)Marshal.SizeOf(typeof(SIX));si.startup.flags=0x100;si.startup.input=ir;si.startup.output=ow;si.startup.error=ew;si.attributes=attr;
                string command=String.Join(" ",new[]{java}.Concat(args).Select(Quote));
                Need(CreateProcessW(java,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,true,0x4|0x10|0x400|0x80000,env,cwd,ref si,out pi),"CREATE_OWNED_SUSPENDED");
                r.identity=new Identity{pid=pi.pid,image=java,job="Local\\font-probe-"+nonce};r.identity.creation=Created(pi.process);r.identity.image=Image(pi.process);
                Need(String.Equals(r.identity.image,java,StringComparison.OrdinalIgnoreCase),"OWNED_IMAGE");Need(AssignProcessToJobObject(job,pi.process),"OWNED_JOB_ASSIGN");bool inside;Need(IsProcessInJob(pi.process,job,out inside)&&inside&&Active(job)==1,"OWNED_JOB_BINDING");
                CloseHandle(ow);ow=IntPtr.Zero;CloseHandle(ew);ew=IntPtr.Zero;Need(ResumeThread(pi.thread)==1,"RESUME_ONE_PROBE");CloseHandle(pi.thread);pi.thread=IntPtr.Zero;
                var clock=Stopwatch.StartNew();uint wait;
                while((wait=WaitForSingleObject(pi.process,50))==258&&clock.ElapsedMilliseconds<30000&&!op.exceeded&&!ep.exceeded){}
                Need(wait==0||wait==258,"PROCESS_WAIT");
                if(wait!=0){r.signalAttempted=true;r.helperClosed=graceful(r.identity);wait=WaitForSingleObject(pi.process,5000);}
                else r.helperClosed=true;
                if(wait!=0)return r;
                Need(Created(pi.process)==r.identity.creation&&String.Equals(Image(pi.process),java,StringComparison.OrdinalIgnoreCase),"FINAL_PROCESS_IDENTITY");
                Need(GetExitCodeProcess(pi.process,out r.exitCode)&&r.exitCode!=259,"WAITED_EXIT_CODE");r.closed=true;r.jobEmpty=Active(job)==0;
                bool oj=op.thread.Join(1000),ej=ep.thread.Join(1000);r.captureClosed=oj&&ej&&op.error==null&&ep.error==null;r.captureExceeded=op.exceeded||ep.exceeded;
                if(r.captureClosed){r.stdout=op.bytes;r.stderr=ep.bytes;}
                if(r.closed&&r.jobEmpty&&r.captureClosed&&r.helperClosed)r.status="CLOSED_OWNED_PROBE";
                return r;
            }
        }catch(Exception error){r.errorCode=System.Text.RegularExpressions.Regex.IsMatch(error.Message??"","\\A[A-Z0-9_]{1,64}\\z")?error.Message:"PROCESS_API_EXCEPTION";return r;}finally{
            if(ow!=IntPtr.Zero)CloseHandle(ow);if(ew!=IntPtr.Zero)CloseHandle(ew);
            if(pi.thread!=IntPtr.Zero)CloseHandle(pi.thread);if(pi.process!=IntPtr.Zero)CloseHandle(pi.process);
            if(job!=IntPtr.Zero)CloseHandle(job); // Explicitly no force-on-close; UNKNOWN remains UNKNOWN.
            if(attrs)DeleteProcThreadAttributeList(attr);if(attr!=IntPtr.Zero)Marshal.FreeHGlobal(attr);if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);if(env!=IntPtr.Zero)Marshal.FreeHGlobal(env);
        }
    }
    public static bool Signal(uint pid,long creation,string image,string jobName){
        IntPtr p=OpenProcess(0x1000|0x100000,false,pid),job=OpenJobObjectW(4,false,jobName);bool attached=false;
        try{
            Need(p!=IntPtr.Zero&&job!=IntPtr.Zero&&WaitForSingleObject(p,0)==258&&Created(p)==creation&&String.Equals(Image(p),Canon(image),StringComparison.OrdinalIgnoreCase),"SIGNAL_OWNED_IDENTITY");
            bool inside;Need(IsProcessInJob(p,job,out inside)&&inside&&Active(job)==1,"SIGNAL_OWNED_JOB");Stamp exe;Read(image,49792,out exe);Need(exe.sha256=="9fcc7d5d43918e389df240d44601c98a4d3aa9e7d0cbbd6d208304e0b574c7e2","SIGNAL_IMAGE_PIN");
            FreeConsole();Need(AttachConsole(pid),"ATTACH_OWNED_CONSOLE");attached=true;Need(SetConsoleCtrlHandler(IntPtr.Zero,true),"SIGNAL_HELPER_IGNORE");
            uint[] members=new uint[3];uint count=GetConsoleProcessList(members,3);Need(count==2&&members.Take(2).Contains(pid)&&members.Take(2).Contains(GetCurrentProcessId()),"ISOLATED_CONSOLE_MEMBERSHIP");
            Need(WaitForSingleObject(p,0)==258&&Created(p)==creation,"SIGNAL_RECHECK");return GenerateConsoleCtrlEvent(0,0); // Exactly one CTRL_C in this isolated console.
        }catch{return false;}finally{if(attached)FreeConsole();if(p!=IntPtr.Zero)CloseHandle(p);if(job!=IntPtr.Zero)CloseHandle(job);}
    }
}
