// vim: ft=cpp sw=4 ts=4 et
/* 
 *             _     (`-')                <-.(`-')                     
 *    <-.     (_)    (OO )_.->      .->    __( OO)           _         
 * (`-')-----.,-(`-')(_| \_)--.(`-')----. '-'---.\    <-.--. \-,-----. 
 * (OO|(_\---'| ( OO)\  `.'  / ( OO).-.  '| .-. (/  (`-'| ,|  |  .--./ 
 *  / |  '--. |  |  ) \    .') ( _) | |  || '-' `.) (OO |(_| /_) (`-') 
 *  \_)  .--'(|  |_/  .'    \   \|  |)|  || /`'.  |,--. |  | ||  |OO ) 
 *   `|  |_)  |  |'->/  .'.  \   '  '-'  '| '--'  /|  '-'  /(_'  '--'\ 
 *    `--'    `--'  `--'   '--'   `-----' `------'  `-----'    `-----'                                                                                                                                     
 *                                                                                                                                    
 * IDA IDC Script that processes the objective-C typeinfo, and names methods accordingly
 *
 * New additions, modifications and bug fixes by fG!
 * (C) fG!, 2012 - reverser@put.as - http://reverse.put.as
 *
 * Original script by: 
 * (C) 2003-2008 Willem Jan Hengeveld <itsme@xs4all.nl> 
 * Web: http://www.xs4all.nl/~itsme/projects/ida/
 *
 * v0.1 - 28/08/2012
 * ChangeLog:
 *  - Add a version number
 *  - Add xrefs to instance methods (I really hate to have to go backwards, too many clicks!)
 *  - Commented some of the code, start cleaning fixmes
 *  - Start adding configurable options
 *  - Rename methods as IDA does with [Class selector] format
 *    This will work with binaries which IDA can correctly process their obj-c info
 *  - Fix the cfstring segment (wasn't working due to wrong segment name)
 *  - change comment type for message and class refs
 *  
 */

// configurable options - YOU CAN MESS AROUND HERE
#define TYPE_INFORMATION NO                          // add type information to names?, I don't like it :-)
// STOP MESSING AROUND BELOW HERE ;-)

#define UNLOADED_FILE   1
#include <idc.idc>

#define YES   1
#define NO    0
#define DEBUG 0

#define STRUCT_OBJC_METHOD_SIZE 12   // sizeof(struct objc_method)

// this script processes the objective C typeinfo tables,
// and names functions accordingly.
// greatly improving the disassembly of objective C programs

static String(ea)
{
     return GetString(ea, -1, ASCSTR_C);
}

static create_mthnames(ea0, ea1, name, type)
{
    auto ea;
    for (ea=ea0 ; ea<ea1 ; ea=ea+STRUCT_OBJC_METHOD_SIZE)
    {
        MakeNameEx(Dword(ea+8), "-["+name+" "+type+" "+String(Dword(ea))+"]", SN_NOCHECK);
    }
}

static fix__objc_binary()
{
    auto rea, ea,segea,name, i, origc,cmt,n,id,type,ofs,size;
    Message("[INFO] Processing __class segment\n");
    // retrieve address of __class segment
    segea=SegByBase(SegByName("__class"));
    // start process valid code/data until the end of this segment
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
    /* 
    @ /usr/include/objc/runtime.h
    
        struct objc_class {
        Class isa;
    
    #if !__OBJC2__
        Class super_class                                        OBJC2_UNAVAILABLE;
        const char *name                                         OBJC2_UNAVAILABLE; // 8
        long version                                             OBJC2_UNAVAILABLE; // 12
        long info                                                OBJC2_UNAVAILABLE; // 16
        long instance_size                                       OBJC2_UNAVAILABLE; // 20
        struct objc_ivar_list *ivars                             OBJC2_UNAVAILABLE; // 24
        struct objc_method_list **methodLists                    OBJC2_UNAVAILABLE; // 28
        struct objc_cache *cache                                 OBJC2_UNAVAILABLE;
        struct objc_protocol_list *protocols                     OBJC2_UNAVAILABLE; 
    #endif
    
    } OBJC2_UNAVAILABLE;
*/
        if (GuessType(ea)=="__class_struct") 
        {
            name=String(Dword(ea+8)); // retrieve class name
#if DEBUG            
            Message("Processing class @ %08lx:%s\n", ea, name);
#endif
            // just rename some fields of the class
            MakeName(ea, form("class_%s", name));               // MakeName will replace invalid chars with '_'
            MakeName(Dword(ea+0x18), form("ivars_%s", name));	// instance vars
            MakeName(Dword(ea+0x1c), form("methods_%s", name));	// methods
            
            /*
            struct objc_method_list {
                struct objc_method_list *obsolete                        OBJC2_UNAVAILABLE;  // 0  
                int method_count                                         OBJC2_UNAVAILABLE;  // 4
                struct objc_method method_list[1]                        OBJC2_UNAVAILABLE;  // 8
            }                                                            OBJC2_UNAVAILABLE;
            struct objc_method {
                SEL method_name                                          OBJC2_UNAVAILABLE;
                char *method_types                                       OBJC2_UNAVAILABLE;
                IMP method_imp                                           OBJC2_UNAVAILABLE;
            }                                                            OBJC2_UNAVAILABLE;
            */

            auto methodLists_ptr, method_count, method_list_start, method_list_end, x;
            
            methodLists_ptr   = Dword(ea+0x1c);
            method_count      = Dword(methodLists_ptr+4);
            method_list_start = methodLists_ptr+8;
            method_list_end   = method_list_start + (STRUCT_OBJC_METHOD_SIZE*method_count);
            
            // name the unnamed functions with method names plus class
            for (x = method_list_start ; x < method_list_end ; x = x + STRUCT_OBJC_METHOD_SIZE)
            {
#if DEBUG
                Message("Processing method %s from class %s @ %x\n", String(Dword(x)), name, x);
#endif
#if TYPE_INFORMATION
                type = " "+String(Dword(x+4));
#else
                type = "";
#endif
                MakeNameEx(Dword(x+8), "-["+name+" "+String(Dword(x))+type+"]", SN_NOCHECK);
            }
	    // todo: create meta_class_methods ( Dword(ea+0x24)
        }
    }
    
    Message("[INFO] Processing __meta_class segment\n");
    segea=SegByBase(SegByName("__meta_class"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__class_struct") {
            name=String(Dword(ea+8));
            Message("%08lx %s\n", ea, name);
            MakeName(ea, form("metaclass_%s", name));
            if (Dword(ea+0x18)) {	// instance vars
                MakeName(Dword(ea+0x18), form("metaivars_%s", name));
            }
            if (Dword(ea+0x1c)) {	// methods
                MakeName(Dword(ea+0x1c), form("metamethods_%s", name));
                create_mthnames(Dword(ea+0x1c)+8, Dword(ea+0x1c)+8+12*Dword(Dword(ea+0x1c)+4), name, "(static)");
            }
	    // todo: meta_class_methods ( Dword(ea+0x24)
        }
    }
    
    Message("[INFO] Processing __protocol segment\n");
    segea=SegByBase(SegByName("__protocol"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__protocol_struct") {
            name=String(Dword(ea+4));
            Message("%08lx %s\n", ea, name);
            if (MakeName(ea, form("protocol_%s", name))) {
                if (Dword(ea+0xc)) {	// instance methods
                    MakeName(Dword(ea+0xc), form("protomth_%s", name));
                }
            }
	    // todo: better handling of name collisions
            else if (MakeName(ea, form("protocol_%s_1", name))) {
                if (Dword(ea+0xc)) {	// instance methods
                    MakeName(Dword(ea+0xc), form("protomth_%s_1", name));
                }
            }
	    // todo: class_methods : Dword(ea+0x10)
        }
    }
    
    Message("[INFO] Processing __category segment\n");
    segea=SegByBase(SegByName("__category"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__category_struct") {
            name=String(Dword(ea+4))+"_"+String(Dword(ea));	// class _ category
            Message("%08lx %s\n", ea, name);
            MakeName(ea, form("category_%s", name));
            if (Dword(ea+0x8)) {	// methods -> seg __cat_inst_meth
                MakeName(Dword(ea+0x8), form("catmths_%s", name));
                create_mthnames(Dword(ea+0x8)+8, Dword(ea+0x8)+8+12*Dword(Dword(ea+0x8)+4), name, "(cat)");
            }
	    // todo: class methods -> __cat_cls_meth
        }
    }
    
    Message("[INFO] Processing __module_info segment\n");
    segea=SegByBase(SegByName("__module_info"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__module_info_struct") {
            MakeName(Dword(ea+0xC), form("symtab_%X", Dword(ea+0xC)));
        }
    }
    
    Message("[INFO] Processing __cfstring segment\n");
    segea=SegByBase(SegByName("__cfstring"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (GuessType(ea)=="__CFString") {
            if (!MakeName(ea, "cfs_"+Name(Dword(ea+8))))
            {
                i=0;
                while (!MakeName(ea, form("cfs_%s_%d",Name(Dword(ea+8)),i)))
                    i++;
            }
            // no more need for this since IDA already comments with the string contents
//             for (rea=DfirstB(ea) ; rea!=BADADDR ; rea=DnextB(ea,rea))
//             {
//                 MakeComm(rea, String(Dword(ea+8)));
//             }
        }
    }
    
    Message("[INFO] Processing __message_refs segment\n");
    segea=SegByBase(SegByName("__message_refs"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (!MakeName(ea, "msg_"+Name(Dword(ea))))
        {
            i=0;
            while (!MakeName(ea, form("msg_%s_%d",Name(Dword(ea)),i)))
                i++;
        }
        for (rea=DfirstB(ea) ; rea!=BADADDR ; rea=DnextB(ea,rea))
        {
            MakeComm(rea, "message: \""+String(Dword(ea))+"\"");
        }
    }
    
    Message("[INFO] Processing __cls_refs segment\n");
    segea=SegByBase(SegByName("__cls_refs"));
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (!MakeName(ea, "cls_"+Name(Dword(ea))))
        {
            i=0;
            while (!MakeName(ea, form("cls_%s_%d",Name(Dword(ea)),i)))
                i++;
        }
        for (rea=DfirstB(ea) ; rea!=BADADDR ; rea=DnextB(ea,rea))
        {
            MakeComm(rea, "class: \""+String(Dword(ea))+"\"");
        }
    }

    Message("[INFO] Processing __instance_vars segment\n");
    segea=SegByBase(SegByName("__instance_vars"));
    for (ea= SegStart(segea) ; ea<SegEnd(segea) ; )
    {
        n=Dword(ea);
        if (n==0) {
            ea=ea+4;
        }
        else {
            id=AddStruc(-1, Name(ea)+"_struct");
            ea=ea+4;
            while (n--) {
                type=String(Dword(ea+4));
                ofs=Dword(ea+8);
                name=String(Dword(ea));
                if (type=="c") { size=1; }
                else if (type=="i") { size=4; }
                else if (type=="I") { size=4; }
                else if (type=="l") { size=4; }
                else if (type=="S") { size=4; }
                else if (type=="q") { size=8; }
                else if (type=="Q") { size=8; }
                else if (type=="B") { size=4; }
                else if (type=="f") { size=4; }
                else if (type=="d") { size=8; }
                else if (substr(type,0,1)=="[") {
                    if (strstr(type,"@")!=-1) {
                        size=4*atol(substr(type,1,-1));
                    }
                    else {
                        Message("%08lx: unrecognized type: %s\n", ea, type);
                        size=4*atol(substr(type,1,-1));
                        if (size==0)
                            size=4;
                    }
                }
                else if (substr(type,0,1)=="@") {
                    size=4;
                }
                else {
                    Message("%08lx: unrecognized type: %s\n", ea, type);
                    size=4;
                }
                AddStrucMember(id, name, ofs, FF_DWRD, -1, size);

                ea=ea+0xc;
            }
        }
    }
    // todo: analyse 'objc_msgSend' calls, and add code refs
    // todo: create class_<name>  and vtbl_<name>  from ivars+methods
    // todo: create __cfString_struct in seg
    // todo: create align 40h  between __class items and __meta_class item  s
    // todo: create align 20h  between __cls_meth, __inst_meth, __instance_vars, __symbols
    // todo: create dword arrays for __eh_frame
    // todo: const_coal contains obj defs + ptr to vtables too
    // todo: rename __pointers -> { __data -> __cString ptrs, __data -> __cfString, ... }
    
    // add xrefs to methods
    // FIXME: there are at least two different structures used in this segment so needs some research
//     segea=SegByBase(SegByName("__cat_inst_meth"));
//     add_catinst_methods_xrefs(segea);
    Message("[INFO] Processing __inst_meth segment\n");
    segea=SegByBase(SegByName("__inst_meth"));
    add_inst_methods_xrefs(segea);
    Message("[INFO] Everything finished!\n");
}

/*
 * function that will add xrefs to category instance methods so we can easily find who's calling each method
 */
static add_catinst_methods_xrefs(segea)
{
    auto cstring, msg_ref, xref, function, ea, advance;
    // start process valid code/data until the end of this segment
    for (ea= SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
        if (Dword(ea) == 0x0 && Dword(ea+4) != 0)
        {
            advance = 8;
        }
        // get the pointer to the correspondent C string we will use to find xrefs
        cstring = Dword(ea);
        // bypass empty strings, usually the header fields of class/methods
        if (SegName(cstring) != "__cstring")
        {
            continue;
        }
        // the function name we will add the xrefs to
        function = Dword(ea+8);
        // now try to find the pointer to message_refs, it's usually the first data xref
        // if there's no pointer to message_refs then there's no xrefs to this method (seems to hold true!)
        msg_ref = DfirstB(cstring);
        // test if it belongs to __message_refs and if not try to find it, if available
        if (SegName(msg_ref) != "__message_refs")
        {
            while(msg_ref != BADADDR)
            {
                msg_ref = DnextB(cstring, msg_ref);
                if (SegName(msg_ref) == "__message_refs")
                {
                    break;
                }
            }
        }
        // if there's no ptr to message_refs then move to next method
        if (msg_ref == BADADDR)
        {
            continue;
        }
    
        // start looking up who's referencing the method
        // the first entry
        xref = DfirstB(msg_ref);
        if (xref != BADADDR)
        {
            // add the xref back to the function in question
            add_dref(xref, function, dr_O);
        }
        // next entries if available
        while (xref != BADADDR)
        {
            xref = DnextB(msg_ref, xref);
            add_dref(xref, function, dr_O);
        }
    }
}
/*
 * function that will add xrefs to instance methods so we can easily find who's calling each method
 */
static add_inst_methods_xrefs(segea)
{
    auto cstring, msg_ref, xref, function, ea;
    // start process valid code/data until the end of this segment
    // XXX: this might need some optimization, for now it just bruteforces
    //      potential problem is padding that exists in some targets and others not
    for (ea=SegStart(segea) ; ea!=BADADDR ; ea=NextHead(ea,SegEnd(segea)))
    {
//         Message("Processing %x\n", ea);
        // get the pointer to the correspondent C string we will use to find xrefs
        cstring = Dword(ea);
        // bypass empty strings, usually the header fields of class/methods
        if (SegName(cstring) != "__cstring")
        {
            continue;
        }
        // the function name we will add the xrefs to
        function = Dword(ea+8);
        // now try to find the pointer to message_refs, it's usually the first data xref
        // if there's no pointer to message_refs then there's no xrefs to this method (seems to hold true!)
        msg_ref = DfirstB(cstring);
        // test if it belongs to __message_refs and if not try to find it, if available
        if (SegName(msg_ref) != "__message_refs")
        {
            while(msg_ref != BADADDR)
            {
                msg_ref = DnextB(cstring, msg_ref);
                if (SegName(msg_ref) == "__message_refs")
                {
                    break;
                }
            }
        }
        // if there's no ptr to message_refs then move to next method
        if (msg_ref == BADADDR)
        {
            continue;
        }
    
        // start looking up who's referencing the method
        // the first entry
        xref = DfirstB(msg_ref);
        if (xref != BADADDR)
        {
            // add the xref back to the function in question
            add_dref(xref, function, dr_O);
        }
        // next entries if available
        while (xref != BADADDR)
        {
            xref = DnextB(msg_ref, xref);
            add_dref(xref, function, dr_O);
        }
    }
}

static main()
{
    fix__objc_binary();
}