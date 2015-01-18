"use strict";
function PECOFF32Binary(filebuffer) {
	var self=this; //use this later on in the forEach blocks to have a reference to this
	
	this.filebuffer=filebuffer;
	
	//Step 1: check if the magic bytes 0x5A4D (MZ) are present at 0x00
	//MZ format: http://wiki.osdev.org/MZ
	if(this.filebuffer.byteLength<2)
		throw "PE file invalid: length < 2";
	this.sigBytes=new Uint8Array(this.filebuffer,0x00,0x02);
	if(Uint8ArrayToHexString(this.sigBytes)!="4D5A")
		throw "PE file invalid: signature != MZ, is: "+Uint8ArrayToHexString(this.sigBytes)+")";
	
	//Step 2: get the PE header offset from 0x3C-0x3F
	if(this.filebuffer.byteLength<0x40)
		throw "PE file invalid: length < 0x40";
	this.peOffset=new Uint32Array(this.filebuffer,0x3C,0x01)[0];
	this.peEnd=this.peOffset+24;
	conlog("PE header offset: 0x"+this.peOffset.toString(16));
	
	//Step 3: get the PE header itself and parse the first header
	//PE format: http://wiki.osdev.org/PE
	if(this.filebuffer.byteLength<this.peEnd)
		throw "PE file invalid: shorter than header";
	this.peHeaderBuf=this.filebuffer.slice(this.peOffset,this.peEnd);
	this.peSigBytes=new Uint8Array(this.peHeaderBuf,0x00,0x04);
	if(Uint8ArrayToHexString(this.peSigBytes)!="50450000")
		throw "PE file invalid: signature != PE\\0\\0 (is: "+Uint8ArrayToHexString(this.peSigBytes)+")";
	this.pe_mMachine=pad((new Uint16Array(this.peHeaderBuf,0x4,1)[0]).toString(16),4,"0").toUpperCase();
	if(this.pe_mMachine!="014C") //todo, if this is ever refactored... remove the x86-only limitation. also todo: what is with different endian platforms in JS and Uint32?
		throw "PE file invalid: machine type != 0x014C, is: "+this.pe_mMachine;
	this.pe_mNumberOfSections=new Uint16Array(this.peHeaderBuf,0x6,1)[0];
	conlog("PE section count: "+this.pe_mNumberOfSections);
	this.pe_mTimeDateStamp=new Uint32Array(this.peHeaderBuf,0x8,1)[0];
	conlog("PE timestamp: "+this.pe_mTimeDateStamp);
	this.pe_mPointerToSymbolTable=new Uint32Array(this.peHeaderBuf,0x0C,1)[0];
	conlog("PE COFF debug symbol table offset: "+(pad(this.pe_mPointerToSymbolTable.toString(16),8,"0")));
	this.pe_mNumberOfSymbols=new Uint32Array(this.peHeaderBuf,0x10,1)[0];
	conlog("PE number of COFF debug symbols: "+(pad(this.pe_mNumberOfSymbols.toString(16),8,"0")));
	this.pe_mSizeOfOptionalHeader=new Uint16Array(this.peHeaderBuf,0x14,1)[0];
	conlog("PE optional header size: "+(pad(this.pe_mSizeOfOptionalHeader.toString(16),4,"0")));
	this.pe_mCharacteristics=new Uint16Array(this.peHeaderBuf,0x16,1)[0];
	this.pe_omCharacteristics={
		IMAGE_FILE_RELOCS_STRIPPED:			(((this.pe_mCharacteristics)&0x0001)>0?true:false),
		IMAGE_FILE_EXECUTABLE_IMAGE:		(((this.pe_mCharacteristics)&0x0002)>0?true:false),
		IMAGE_FILE_LINE_NUMS_STRIPPED:		(((this.pe_mCharacteristics)&0x0004)>0?true:false),
		IMAGE_FILE_LOCAL_SYMS_STRIPPED:		(((this.pe_mCharacteristics)&0x0008)>0?true:false),
		IMAGE_FILE_AGGRESSIVE_WS_TRIM:		(((this.pe_mCharacteristics)&0x0010)>0?true:false),
		IMAGE_FILE_LARGE_ADDRESS_AWARE:		(((this.pe_mCharacteristics)&0x0020)>0?true:false),
		IMAGE_FILE_RESERVED:				(((this.pe_mCharacteristics)&0x0040)>0?true:false),
		IMAGE_FILE_BYTES_REVERSED_LO:		(((this.pe_mCharacteristics)&0x0080)>0?true:false),
		IMAGE_FILE_32BIT_MACHINE:			(((this.pe_mCharacteristics)&0x0100)>0?true:false),
		IMAGE_FILE_DEBUG_STRIPPED:			(((this.pe_mCharacteristics)&0x0200)>0?true:false),
		IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:	(((this.pe_mCharacteristics)&0x0400)>0?true:false),
		IMAGE_FILE_NET_RUN_FROM_SWAP:		(((this.pe_mCharacteristics)&0x0800)>0?true:false),
		IMAGE_FILE_SYSTEM:					(((this.pe_mCharacteristics)&0x1000)>0?true:false),
		IMAGE_FILE_DLL:						(((this.pe_mCharacteristics)&0x2000)>0?true:false),
		IMAGE_FILE_UP_SYSTEM_ONLY:			(((this.pe_mCharacteristics)&0x4000)>0?true:false),
		IMAGE_FILE_BYTES_REVERSED_HI:		(((this.pe_mCharacteristics)&0x8000)>0?true:false)
	}
	this.pe_smCharacteristics="";
	for(var k in this.pe_omCharacteristics)
		if(this.pe_omCharacteristics[k]) this.pe_smCharacteristics+=k+",";
	conlog("PE characteristics: "+(pad(this.pe_mCharacteristics.toString(16),4,"0"))+" ("+this.pe_smCharacteristics+")");
	
	//Step 4: Optional header (if present)
	//Todo: when factoring this into a generic PE parser, remove the check for presence (obj files dont need it)
	if(this.pe_mSizeOfOptionalHeader==0)
		throw "PE file invalid: no extended header";
	this.pe_extEnd=this.peEnd+this.pe_mSizeOfOptionalHeader;
	if(this.filebuffer.byteLength<this.pe_extEnd)
		throw "PE file invalid: extended header corrupted"
	conlog("PE extended header, begin "+(pad(this.peEnd.toString(16),8,"0"))+", end "+(pad(this.pe_extEnd.toString(16),8,"0")));
	this.peExtBuf=this.filebuffer.slice(this.peEnd,this.pe_extEnd);
	this.peext_mMagic=new Uint16Array(this.peExtBuf,0x00,1)[0];
	conlog("PE extended header, magic: "+(pad(this.peext_mMagic.toString(16),4,"0")));
	if(this.peext_mMagic!=0x010b) // && this.peext_mMagic!=0x020b) //todo: support 64-bit PE32+
		throw "PE file invalid: extended header has invalid signature"
	this.peext_mMajorLinkerVersion=new Uint8Array(this.peExtBuf,0x02,1)[0];
	this.peext_mMinorLinkerVersion=new Uint8Array(this.peExtBuf,0x03,1)[0];
	conlog("PE extended header, linker version: maj "+(pad(this.peext_mMajorLinkerVersion.toString(16),2,"0"))+", min "+(pad(this.peext_mMinorLinkerVersion.toString(16),2,"0")));
	
	this.peext_mSizeOfCode=new Uint32Array(this.peExtBuf,0x04,1)[0];
	conlog("PE extended header, size of code: "+(pad(this.peext_mSizeOfCode.toString(16),8,"0")));
	
	this.peext_mSizeOfInitializedData=new Uint32Array(this.peExtBuf,0x08,1)[0];
	conlog("PE extended header, size of initialized data: "+(pad(this.peext_mSizeOfInitializedData.toString(16),8,"0")));
	
	this.peext_mSizeOfUninitializedData=new Uint32Array(this.peExtBuf,0x0C,1)[0];
	conlog("PE extended header, size of uninitialized data: "+(pad(this.peext_mSizeOfUninitializedData.toString(16),8,"0")));
	
	this.peext_mAddressOfEntryPoint=new Uint32Array(this.peExtBuf,0x010,1)[0];
	conlog("PE extended header, address of entry point: "+(pad(this.peext_mAddressOfEntryPoint.toString(16),8,"0")));
	
	this.peext_mBaseOfCode=new Uint32Array(this.peExtBuf,0x14,1)[0];
	conlog("PE extended header, base of code: "+(pad(this.peext_mBaseOfCode.toString(16),8,"0")));
	
	this.peext_mBaseOfData=new Uint32Array(this.peExtBuf,0x18,1)[0];
	conlog("PE extended header, base of data: "+(pad(this.peext_mBaseOfData.toString(16),8,"0")));
	
	this.peext_mImageBase=new Uint32Array(this.peExtBuf,0x1C,1)[0];
	conlog("PE extended header, image base: "+(pad(this.peext_mImageBase.toString(16),8,"0")));
	
	this.peext_mSectionAlignment=new Uint32Array(this.peExtBuf,0x20,1)[0];
	conlog("PE extended header, section alignment: "+(pad(this.peext_mSectionAlignment.toString(16),8,"0")));
	
	this.peext_mFileAlignment=new Uint32Array(this.peExtBuf,0x24,1)[0];
	conlog("PE extended header, file alignment: "+(pad(this.peext_mFileAlignment.toString(16),8,"0")));
	
	this.peext_mMajorOperatingSystemVersion=new Uint16Array(this.peExtBuf,0x28,1)[0];
	this.peext_mMinorOperatingSystemVersion=new Uint16Array(this.peExtBuf,0x2A,1)[0];
	conlog("PE extended header, OS version: maj "+(pad(this.peext_mMajorOperatingSystemVersion.toString(16),4,"0"))+", min "+(pad(this.peext_mMinorOperatingSystemVersion.toString(16),4,"0")));
	
	this.peext_mMajorImageVersion=new Uint16Array(this.peExtBuf,0x2C,1)[0];
	this.peext_mMinorImageVersion=new Uint16Array(this.peExtBuf,0x2E,1)[0];
	conlog("PE extended header, image version: "+(pad(this.peext_mMajorImageVersion.toString(16),4,"0"))+", min "+(pad(this.peext_mMinorImageVersion.toString(16),4,"0")));
	
	this.peext_mMajorSubsystemVersion=new Uint16Array(this.peExtBuf,0x30,1)[0];
	this.peext_mMinorSubsystemVersion=new Uint16Array(this.peExtBuf,0x32,1)[0];
	conlog("PE extended header, subsystem version: "+(pad(this.peext_mMajorSubsystemVersion.toString(16),4,"0"))+", min "+(pad(this.peext_mMinorSubsystemVersion.toString(16),4,"0")));
	
	this.peext_mWin32VersionValue=new Uint32Array(this.peExtBuf,0x34,1)[0];
	conlog("PE extended header, win32 version: "+(pad(this.peext_mWin32VersionValue.toString(16),8,"0")));
	
	this.peext_mSizeOfImage=new Uint32Array(this.peExtBuf,0x38,1)[0];
	conlog("PE extended header, size of image: "+(pad(this.peext_mSizeOfImage.toString(16),8,"0")));
	
	this.peext_mSizeOfHeaders=new Uint32Array(this.peExtBuf,0x3C,1)[0];
	conlog("PE extended header, size of headers: "+(pad(this.peext_mSizeOfHeaders.toString(16),8,"0")));
	
	this.peext_mCheckSum=new Uint32Array(this.peExtBuf,0x40,1)[0];
	conlog("PE extended header, checksum: "+(pad(this.peext_mCheckSum.toString(16),8,"0")));
	
	this.peext_mSubsystem=new Uint16Array(this.peExtBuf,0x44,1)[0];
	this.peext_smSubsystem="INVALID";
	switch(this.peext_mSubsystem) {
		case 0: this.peext_smSubsystem="UNKNOWN"; break;
		case 1: this.peext_smSubsystem="NATIVE"; break;
		case 2: this.peext_smSubsystem="WINDOWS_GUI"; break;
		case 3: this.peext_smSubsystem="WINDOWS_CLI"; break;
		case 7: this.peext_smSubsystem="POSIX_CLI"; break;
		case 9: this.peext_smSubsystem="WINCE_GUI"; break;
		case 10: this.peext_smSubsystem="EFI_APP"; break;
		case 11: this.peext_smSubsystem="EFI_BOOT_DRIVER"; break;
		case 12: this.peext_smSubsystem="EFI_RUNTIME_DRIVER"; break;
		case 13: this.peext_smSubsystem="EFI_ROM"; break;
		case 14: this.peext_smSubsystem="XBOX"; break;
		default: this.peext_smSubsystem="INVALID"; break;
	}
	conlog("PE extended header, subsystem: "+(pad(this.peext_mSubsystem.toString(16),4,"0"))+" ("+this.peext_smSubsystem+")");
	
	this.peext_mDllCharacteristics=new Uint16Array(this.peExtBuf,0x46,1)[0];
	conlog("PE extended header, DLL characteristics: "+(pad(this.peext_mDllCharacteristics.toString(16),4,"0")));
	
	this.peext_mSizeOfStackReserve=new Uint32Array(this.peExtBuf,0x48,1)[0];
	conlog("PE extended header, size of stack reserve: "+(pad(this.peext_mSizeOfStackReserve.toString(16),8,"0")));
	
	this.peext_mSizeOfStackCommit=new Uint32Array(this.peExtBuf,0x4C,1)[0];
	conlog("PE extended header, size of stack commit: "+(pad(this.peext_mSizeOfStackCommit.toString(16),8,"0")));
	
	this.peext_mSizeOfHeapReserve=new Uint32Array(this.peExtBuf,0x50,1)[0];
	conlog("PE extended header, size of heap reserve: "+(pad(this.peext_mSizeOfHeapReserve.toString(16),8,"0")));
	
	this.peext_mSizeOfHeapCommit=new Uint32Array(this.peExtBuf,0x54,1)[0];
	conlog("PE extended header, size of heap commit: "+(pad(this.peext_mSizeOfHeapCommit.toString(16),8,"0")));
	
	this.peext_mLoaderFlags=new Uint32Array(this.peExtBuf,0x58,1)[0];
	conlog("PE extended header, loader flags: "+(pad(this.peext_mLoaderFlags.toString(16),8,"0")));
	
	this.peext_mNumberOfRvaAndSizes=new Uint32Array(this.peExtBuf,0x5C,1)[0];
	conlog("PE extended header, number of RVA and sizes: "+(pad(this.peext_mNumberOfRvaAndSizes.toString(16),8,"0")));
	
	//Step 5: RVA table directory
	this.rvaBegin=this.peEnd+0x60;
	this.rvaEnd=this.rvaBegin+this.peext_mNumberOfRvaAndSizes*8; //2 DWORDs each
	if(this.filebuffer.byteLength<this.rvaEnd)
		throw "PE file invalid, RVA table directory corrupted"
	this.rvatables=["export","import","resource","exception","certificate","base_relocation","debug","architecture","globalptr","tls","loadconfig","boundimport","iat","delayimportdescriptor","clrruntime","reserved"];
	if(this.peext_mNumberOfRvaAndSizes>this.rvatables.length)
		throw "PE file invalid, too many tables in RVA table directory";
	conlog("PE RVA table directory, begin "+(pad(this.rvaBegin.toString(16),8,"0"))+", end "+(pad(this.rvaEnd.toString(16),8,"0")));
	this.rvaBuf=this.filebuffer.slice(this.rvaBegin,this.rvaEnd);
	this.pe_rvaTables=[];
	for(var i=0;i<this.peext_mNumberOfRvaAndSizes;i++) {
		var rva_entry_a=new Uint32Array(this.rvaBuf,(i*0x8),2);
		var rva_entry_rva=rva_entry_a[0];
		var rva_entry_size=rva_entry_a[1];
		this.pe_rvaTables.push({
			index:i,
			key:this.rvatables[i],
			rva:rva_entry_rva,
			size:rva_entry_size
		});
		conlog("PE RVA table directory entry "+this.rvatables[i]+", RVA "+(pad(rva_entry_rva.toString(16),8,"0"))+", size "+(pad(rva_entry_size.toString(16),8,"0")));
	}
	
	//Step 6: section header block
	this.shBegin=this.rvaEnd;
	this.shEnd=this.shBegin+this.pe_mNumberOfSections*0x28; //sizeof IMAGE_SECTION_HEADER
	if(this.filebuffer.byteLength<this.shEnd)
		throw "PE file invalid, section table corrupted";
	this.shBuf=this.filebuffer.slice(this.shBegin,this.shEnd);
	conlog("PE section table, begin "+(pad(this.shBegin.toString(16),8,"0"))+", end "+(pad(this.shEnd.toString(16),8,"0")));
	this.pe_sections=[];
	for(var i=0;i<this.pe_mNumberOfSections;i++) {
		var sh_offset=i*0x28;
		var sh_name=Uint8ArrayToString(new Uint8Array(this.shBuf,sh_offset+0x00,8));
		var sh_mVirtualSize=new Uint32Array(this.shBuf,sh_offset+0x08,1)[0];
		var sh_mVirtualAddress=new Uint32Array(this.shBuf,sh_offset+0x0C,1)[0];
		var sh_mSizeOfRawData=new Uint32Array(this.shBuf,sh_offset+0x10,1)[0];
		var sh_mPointerToRawData=new Uint32Array(this.shBuf,sh_offset+0x14,1)[0];//todo this is wrong in osdev wiki
		var sh_mPointerToRelocations=new Uint32Array(this.shBuf,sh_offset+0x18,1)[0];
		var sh_mPointerToLinenumbers=new Uint32Array(this.shBuf,sh_offset+0x1C,1)[0];
		var sh_mNumberOfRelocations=new Uint16Array(this.shBuf,sh_offset+0x20,1)[0];
		var sh_mNumberOfLinenumbers=new Uint16Array(this.shBuf,sh_offset+0x22,1)[0];
		var sh_mCharacteristics=new Uint32Array(this.shBuf,sh_offset+0x24,1)[0];
		conlog("PE section table entry "+i+", name "+sh_name+", virtual size "+(pad(sh_mVirtualSize.toString(16),8,"0"))+", virtual address "+(pad(sh_mVirtualAddress.toString(16),8,"0"))+", raw data size "+(pad(sh_mSizeOfRawData.toString(16),8,"0"))+", pointer to raw data "+(pad(sh_mPointerToRawData.toString(16),8,"0"))+", pointer to relocations "+(pad(sh_mPointerToRelocations.toString(16),8,"0"))+", pointer to line numbers "+(pad(sh_mPointerToLinenumbers.toString(16),8,"0"))+", number of relocations "+(pad(sh_mNumberOfRelocations.toString(16),4,"0"))+", number of line numbers "+(pad(sh_mNumberOfLinenumbers.toString(16),8,"0"))+", characteristics "+(pad(sh_mCharacteristics.toString(16),8,"0")));
		this.pe_sections.push({
			index:i,
			name:sh_name,
			mVirtualSize:sh_mVirtualSize,
			mVirtualAddress:sh_mVirtualAddress,
			mSizeOfRawData:sh_mSizeOfRawData,
			mPointerToRawData:sh_mPointerToRawData,
			mPointerToRelocations:sh_mPointerToRelocations,
			mPointerToLinenumbers:sh_mPointerToLinenumbers,
			mNumberOfRelocations:sh_mNumberOfRelocations,
			mNumberOfLinenumbers:sh_mNumberOfLinenumbers,
			mCharacteristics:sh_mCharacteristics,
			type:1,
			comment:""
		});
	}
	if(this.pe_sections.length==0)
		throw "PE file invalid: no sections found";
	
	//Step 7: Order the sections by raw address ascending
	//According to PE/COFF spec, this should be the case already
	//but we need to sort so that we can find out if there's a gap
	//which can be used to store data (steganography? RTTI info?)
	//The file header is mapped to the base address
	this.pe_sections.unshift({
		index:-1,
		name:"_PEHEAD",
		mVirtualSize:this.peext_mSizeOfHeaders,
		mVirtualAddress:0,
		mSizeOfRawData:this.peext_mSizeOfHeaders,
		mPointerToRawData:0, //first byte
		mPointerToRelocations:-1,
		mPointerToLinenumbers:-1,
		mNumberOfRelocations:-1,
		mNumberOfLinenumbers:-1,
		mCharacteristics:-1,
		type:1,
		comment:"PE file header. Always mapped to image base"
	});
	if(this.pe_sections[1].mPointerToRawData!=this.shEnd) {
		conlog("Gap in PE file: "+pad((this.pe_sections[1].mPointerToRawData-this.shEnd).toString(16),8,"0")+" bytes missing - section block ends at "+pad(this.shEnd.toString(16),8,"0")+", first section begins at "+pad(this.pe_sections[1].mPointerToRawData.toString(16),8,"0"));
		//Insert a "virtual" section, we have to account for each byte in the binary in the resulting assembly
		this.pe_sections.unshift({
			index:-1,
			name:"_GAP",
			mVirtualSize:-1,
			mVirtualAddress:-1,
			mSizeOfRawData:this.pe_sections[1].mPointerToRawData-this.shEnd,
			mPointerToRawData:this.shEnd,
			mPointerToRelocations:-1,
			mPointerToLinenumbers:-1,
			mNumberOfRelocations:-1,
			mNumberOfLinenumbers:-1,
			mCharacteristics:-1,
			type:0,
			comment:"Gap section between end of sections block and first section"
		});
	}
	this.pe_sections.sort(function(a,b) {
		if(a.mPointerToRawData<b.mPointerToRawData)
			return -1;
		else if(a.mPointerToRawData>b.mPointerToRawData)
			return 1;
		else //it may be that this is actually valid, no idea
			throw "PE file invalid: sections "+a.index+" ("+a.name+") and "+b.index+" ("+b.name+") have same raw offset "+pad(a.mPointerToRawData.toString(16),8,"0");
	});
	//Todo: implement insertion of gaps BETWEEN sections
	//There's just too many places to hide stuff in for viruses...
	//After the sorting and the possible insertion of a gap section, we have to ren
	for(var i=0;i<this.pe_sections.length;i++) {
		this.pe_sections[i].index=i;
	}
	
	//Step 8: Parse exports, if present
	if(this.pe_rvaTables[0] && this.pe_rvaTables[0].rva && this.pe_rvaTables[0].size) {
		{
			var found=-1;
			for(var i=0;i<this.pe_sections.length;i++) {
				var s=this.pe_sections[i];
				if(s.mVirtualAddress==this.pe_rvaTables[0].rva) {
					found=i;
					break;
				}
			}
			if(found==-1)
				throw "PE file invalid: Export section specified in RVA table, but could not locate section";
			this.edata_begin=this.pe_sections[found].mPointerToRawData;
			this.edata_end=this.edata_begin+this.pe_sections[found].mSizeOfRawData;
			this.edata_vbegin=this.pe_sections[found].mVirtualAddress;
			this.edata_vend=this.edata_vbegin+this.pe_sections[found].mVirtualSize;
			
			conlog("PE edata section at #"+found+", begin at "+pad(this.edata_begin.toString(16),8,"0")+", end at "+pad(this.edata_end.toString(16),8,"0")+", virtual begin at "+pad(this.edata_vbegin.toString(16),8,"0")+", end at "+pad(this.edata_vend.toString(16),8,"0"));
			this.edata_buf=this.filebuffer.slice(this.edata_begin,this.edata_end);
			
			this.edata_edtbuf=this.edata_buf.slice(0,0x28);
			
			this.edata_edt_exportflags=new Uint32Array(this.edata_edtbuf,0x00,1)[0];
			conlog("PE edata section, export directory table: exportflags "+toHex(this.edata_edt_exportflags,4));
			
			this.edata_edt_timestamp=new Uint32Array(this.edata_edtbuf,0x04,1)[0];
			conlog("PE edata section, export directory table: timestamp "+toHex(this.edata_edt_timestamp,4));
			
			this.edata_edt_majver=new Uint16Array(this.edata_edtbuf,0x08,1)[0];
			this.edata_edt_minver=new Uint16Array(this.edata_edtbuf,0x0A,1)[0];
			conlog("PE edata section, export directory table: version maj "+toHex(this.edata_edt_majver,2)+", min "+toHex(this.edata_edt_minver,2));
			
			this.edata_edt_namerva=new Uint32Array(this.edata_edtbuf,0x0C,1)[0];
			conlog("PE edata section, export directory table: Name RVA "+toHex(this.edata_edt_namerva,4));
			
			this.edata_edt_ordinalbase=new Uint32Array(this.edata_edtbuf,0x10,1)[0];
			conlog("PE edata section, export directory table: Ordinal base "+toHex(this.edata_edt_ordinalbase,4));
			
			this.edata_edt_eatentries=new Uint32Array(this.edata_edtbuf,0x14,1)[0];
			conlog("PE edata section, export directory table: EAT entries "+toHex(this.edata_edt_eatentries,4));
			
			this.edata_edt_numnamepointers=new Uint32Array(this.edata_edtbuf,0x18,1)[0];
			conlog("PE edata section, export directory table: Number of name pointers "+toHex(this.edata_edt_numnamepointers,4));
			
			this.edata_edt_eatrva=new Uint32Array(this.edata_edtbuf,0x1C,1)[0];
			conlog("PE edata section, export directory table: EAT RVA "+toHex(this.edata_edt_eatrva,4));
			
			this.edata_edt_nprva=new Uint32Array(this.edata_edtbuf,0x20,1)[0];
			conlog("PE edata section, export directory table: Name pointer RVA "+toHex(this.edata_edt_nprva,4));
			
			this.edata_edt_otrva=new Uint32Array(this.edata_edtbuf,0x24,1)[0];
			conlog("PE edata section, export directory table: Ordinal Table RVA "+toHex(this.edata_edt_otrva,4));
			
			//For reasons unknown, the RVA values may also target into another section. Interesting to check if other PE analyzers get thrown off by such a binary
			//We are not. Or, to specify, we crash gracefully.
			//And after we check the RVAs for validity, we rebase them relative to edata section...
			if(this.edata_edt_namerva<this.edata_vbegin || this.edata_edt_namerva>this.edata_vend)
				throw "PE file invalid, EDT Name RVA outside of edata section range";
			this.edata_edt_namerva-=this.edata_vbegin;
			if(this.edata_edt_eatrva<this.edata_vbegin || this.edata_edt_eatrva>this.edata_vend)
				throw "PE file invalid, EDT EAT RVA outside of edata section range";
			this.edata_edt_eatrva-=this.edata_vbegin;
			if(this.edata_edt_nprva<this.edata_vbegin || this.edata_edt_nprva>this.edata_vend)
				throw "PE file invalid, EDT NP RVA outside of edata section range";
			this.edata_edt_nprva-=this.edata_vbegin;
			if(this.edata_edt_otrva<this.edata_vbegin || this.edata_edt_otrva>this.edata_vend)
				throw "PE file invalid, EDT OT RVA outside of edata section range";
			this.edata_edt_otrva-=this.edata_vbegin;
			
			//Extract the name, use a ceiling of 256 bytes for the length
			var namebuf=this.edata_buf.slice(this.edata_edt_namerva,this.edata_edt_namerva+256);
			this.edata_imagename=Uint8ArrayToString(new Uint8Array(namebuf));
			conlog("PE edata section, original image name '"+this.edata_imagename+"'");
			namebuf=null;
			
			//Parse EAT (export address table)
			this.edata_eat_entries=[];
			for(var i=0;i<this.edata_edt_eatentries;i++) {
				var rva=new Uint32Array(this.edata_buf,this.edata_edt_eatrva+i*0x4,1)[0];
				conlog("PE edata section, EAT entry "+i+" at offset "+toHex(this.edata_edt_eatrva+i*0x4,4)+", ordinal "+(this.edata_edt_ordinalbase+i)+", rva "+toHex(rva,4));
				this.edata_eat_entries.push({
					ordinal:this.edata_edt_ordinalbase+i,
					rva:rva,
					index:i,
				});
			}
			
			//Parse Name Pointer table
			this.edata_npt_entries=[];
			for(var i=0;i<this.edata_edt_numnamepointers;i++) {
				var rva=new Uint32Array(this.edata_buf,this.edata_edt_nprva+i*0x4,1)[0]-this.edata_vbegin;
				var str=Uint8ArrayToString(new Uint8Array(this.edata_buf.slice(rva,rva+256)));
				conlog("PE edata section, NPT entry "+i+" at offset "+toHex(this.edata_edt_nprva+i*0x4,4)+", rva "+toHex(rva,4)+", string at rva '"+str+"'");
				this.edata_npt_entries.push({
					rva:rva,
					str:str,
					index:i,
				});
			}
			
			//Parse Ordinal Table
			this.edata_ot_entries=[];
			//According to spec, NPT and OT are "parallel arrays", so no separate size field for OT
			for(var i=0;i<this.edata_edt_numnamepointers;i++) {
				var ord=new Uint16Array(this.edata_buf,this.edata_edt_otrva+i*0x2,1)[0];
				conlog("PE edata section, OT entry "+i+" at offset "+toHex(this.edata_edt_otrva+i*0x2,4)+", ord "+toHex(ord,2));
				this.edata_ot_entries.push({
					ord:ord,
					index:i,
				});
			}
			
			//Combine the export tables together
			this.exports=[];
			this.edata_eat_entries.forEach(function(e,i) {
				var obj={
					ordinal:e.ordinal,
					rva:e.rva,
					name:""
				}
				//Now, search all export names and check if their ordinal is the one of the current entry
				//This is dog slow, but reverse-search was not ever intended in the format...
				self.edata_ot_entries.forEach(function(e2,i2) {
					if(self.edata_edt_ordinalbase+e2.ord==e.ordinal) {
						obj.name=self.edata_npt_entries[e2.index].str;
					}
				});
				self.exports.push(obj);
			});
		}
	} else {
		this.exports=[];
		conlog("This PE file has no export table");
	}
	
	//Step 9: Parse imports, if present
	if(this.pe_rvaTables[1] && this.pe_rvaTables[1].rva && this.pe_rvaTables[1].size) {
		{
			var found=-1;
			for(var i=0;i<this.pe_sections.length;i++) {
				var s=this.pe_sections[i];
				if(s.mVirtualAddress==this.pe_rvaTables[1].rva) {
					found=i;
					break;
				}
			}
			if(found==-1)
				throw "PE file invalid: Import section specified in RVA table, but could not locate section";
			this.idata_begin=this.pe_sections[found].mPointerToRawData;
			this.idata_end=this.idata_begin+this.pe_sections[found].mSizeOfRawData;
			this.idata_vbegin=this.pe_sections[found].mVirtualAddress;
			this.idata_vend=this.idata_vbegin+this.pe_sections[found].mVirtualSize;
			
			conlog("PE idata section at #"+found+", begin at "+pad(this.idata_begin.toString(16),8,"0")+", end at "+pad(this.idata_end.toString(16),8,"0")+", virtual begin at "+pad(this.idata_vbegin.toString(16),8,"0")+", end at "+pad(this.idata_vend.toString(16),8,"0"));
			this.idata_buf=this.filebuffer.slice(this.idata_begin,this.idata_end);
			
			//Parse IDT (Import Directory Table)
			this.idata_idt_entries=[];
			{
			var i=0;
			while(true) {
				var entrybuf=this.idata_buf.slice(i*0x14,(i+1)*0x14);
				conlog("PE idata section, IDT entry "+i+", begin at "+toHex(i*0x14,4)+", end at "+toHex((i+1)*0x14,4));
				
				var obj={};
				obj.ilt_rva=new Uint32Array(entrybuf,0x00,1)[0];
				if(obj.ilt_rva==0) { //stop parsing at nullpointer
					conlog("PE idata section, hit NULL IDT entry");
					break;
				}
				
				obj.ilt_rva-=this.idata_vbegin;
				conlog("PE idata section, IDT entry "+i+", ILT RVA "+toHex(obj.ilt_rva,4));
				
				obj.timestamp=new Uint32Array(entrybuf,0x04,1)[0];
				conlog("PE idata section, IDT entry "+i+", timestamp "+toHex(obj.timestamp,4));
				
				obj.forwarderchain=new Uint32Array(entrybuf,0x08,1)[0];
				conlog("PE idata section, IDT entry "+i+", forwarder chain "+toHex(obj.forwarderchain,4));
				
				obj.name_rva=new Uint32Array(entrybuf,0x0C,1)[0]-this.idata_vbegin;
				obj.name_str=Uint8ArrayToString(new Uint8Array(this.idata_buf.slice(obj.name_rva,obj.name_rva+256)));
				conlog("PE idata section, IDT entry "+i+", name RVA "+toHex(obj.name_rva,4)+", string at RVA '"+obj.name_str+"'");
				
				obj.iat_rva=new Uint32Array(entrybuf,0x10,1)[0];
				conlog("PE idata section, IDT entry "+i+", IAT RVA "+toHex(obj.iat_rva,4));
				
				obj.imports=[];
				{
				var j=0;
				while(true) {
					var entry=new Uint32Array(this.idata_buf,obj.ilt_rva+j*0x4,1)[0];
					if(entry==0) {
						conlog("PE idata section, IDT entry "+i+", ILT entry "+j+" at offset "+toHex(obj.ilt_rva+j*0x4,4)+" is NULL");
						break;
					}
					if((entry & 0x80000000)!=0) { //Import by ordinal
						throw "PE file uses import by ordinal, this is not supported yet!";
					} else { //Import by name, this is an RVA to a hint/name table entry
						entry-=this.idata_vbegin;
						var hint=new Uint16Array(this.idata_buf,entry,1)[0];
						var name=Uint8ArrayToString(new Uint8Array(this.idata_buf.slice(entry+2,entry+2+256)));
						var iat_addr=obj.iat_rva+j*0x4;
						conlog("PE idata section, IDT entry "+i+", ILT entry "+j+" at offset "+toHex(obj.ilt_rva+j*0x4,4)+", pointer to hint/name table "+toHex(entry,4)+", hint "+toHex(hint,2)+", name '"+name+"', actual address will be placed at "+toHex(iat_addr,4));
						obj.imports.push({
							hint:hint,
							name:name,
							rva:iat_addr,
						});
					}
					j++;
				}
				}
				this.idata_idt_entries.push(obj);
				
				i++;
			}
			}
			
			this.imports=[];
			this.idata_idt_entries.forEach(function(e) {
				self.imports.push({
					name:e.name_str,
					imports:e.imports,
				});
			});
		}
	} else {
		this.imports=[];
		conlog("This PE file has no import table");
	}
	//Step 10: Parse resources, if present
	//Step 11: Parse SEH records, if present
	//Step 12: Parse certificate, if present
	//Step 13: Parse relocation table, if present
	//Step 14: Parse debug table, if present
	//Step 15: Parse "architecture" table, if present
	//Step 16: Parse "globalptr" table, if present
	//Step 17: Parse "tls" table, if present
	//Step 18: Parse "loadconfig" table, if present
	//Step 19: Parse "boundimport" table, if present
	//Step 20: Parse "iat" table, if present
	//Step 21: Parse "delayimportdescriptor" table, if present
	//Step 22: Parse "clrruntime" table, if present
	
	//Step 23: Copy the information from pe_sections into the standard array
	this.sections=[];
	for(var i=0;i<this.pe_sections.length;i++) {
		var buf=ArrayBuffer.transfer(this.filebuffer,Math.max(this.pe_sections[i].mVirtualSize,this.pe_sections[i].mSizeOfRawData));
		this.sections.push({
			type:this.pe_sections[i].type,
			name:this.pe_sections[i].name,
			va:this.pe_sections[i].mVirtualAddress+this.peext_mImageBase,
			vsize:this.pe_sections[i].mVirtualSize,
			fa:this.pe_sections[i].mPointerToRawData,
			fsize:this.pe_sections[i].mSizeOfRawData,
			comment:this.pe_sections[i].comment,
			buffer:buf
		});
	}
}