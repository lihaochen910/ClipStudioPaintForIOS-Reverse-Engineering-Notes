// 逆向中整理的一些frida方法

// xia0 log
function XLOG ( log ) {
	console.log ( "[*] " + log )
}

function XLibLOG ( log ) {
	console.log ( log )
}

// format string with width
function format ( str, width ) {
	str = str + ""
	var len = str.length;

	if ( len > width ) {
		return str
	}

	for ( var i = 0; i < width - len; i++ ) {
		str += " "
	}
	return str;
}

function get_image_vm_slide ( modulePath ) {
	// intptr_t   _dyld_get_image_vmaddr_slide(uint32_t image_index)
	var _dyld_get_image_vmaddr_slide = new NativeFunction (
		Module.findExportByName ( null, '_dyld_get_image_vmaddr_slide' ),
		'pointer',
		[ 'uint32' ]
	);
	// const char*  _dyld_get_image_name(uint32_t image_index)
	var _dyld_get_image_name = new NativeFunction (
		Module.findExportByName ( null, '_dyld_get_image_name' ),
		'pointer',
		[ 'uint32' ]
	);
	// uint32_t  _dyld_image_count(void)
	var _dyld_image_count = new NativeFunction (
		Module.findExportByName ( null, '_dyld_image_count' ),
		'uint32',
		[]
	);

	var image_count = _dyld_image_count ();

	for ( var i = 0; i < image_count; i++ ) {
		var image_name_ptr = _dyld_get_image_name ( i )
		var image_silde_ptr = _dyld_get_image_vmaddr_slide ( i )
		var image_name = Memory.readUtf8String ( image_name_ptr )

		if ( image_name == modulePath ) {
			//XLOG(Memory.readUtf8String(image_name_ptr) + " slide:"+image_silde_ptr)
			return image_silde_ptr;
		}
		//XLOG(Memory.readUtf8String(image_name_ptr) + "slide:"+image_silde_ptr)
	}

	return 0;
}

function get_all_objc_class ( modulePath ) {

	// const char * objc_copyClassNamesForImage(const char *image, unsigned int *outCount)
	var objc_copyClassNamesForImage = new NativeFunction (
		Module.findExportByName ( null, 'objc_copyClassNamesForImage' ),
		'pointer',
		[ 'pointer', 'pointer' ]
	);
	// free
	var free = new NativeFunction ( Module.findExportByName ( null, 'free' ), 'void', [ 'pointer' ] );

	// if given modulePath nil, default is mainBundle
	if ( !modulePath ) {
		var path = ObjC.classes.NSBundle.mainBundle ().executablePath ().UTF8String ();
	} else {
		var path = modulePath;
	}

	// create args
	var pPath = Memory.allocUtf8String ( path );
	var p = Memory.alloc ( Process.pointerSize );
	Memory.writeUInt ( p, 0 );

	var pClasses = objc_copyClassNamesForImage ( pPath, p );
	var count = Memory.readUInt ( p );
	var classes = new Array ( count );

	for ( var i = 0; i < count; i++ ) {
		var pClassName = Memory.readPointer ( pClasses.add ( i * Process.pointerSize ) );
		classes[ i ] = Memory.readUtf8String ( pClassName );
	}

	free ( pClasses );

	// XLOG(classes)
	return classes;
}


function get_all_class_methods ( classname ) {
	var objc_getClass = new NativeFunction (
		Module.findExportByName ( null, 'objc_getClass' ),
		'pointer',
		[ 'pointer' ]
	);
	var class_copyMethodList = new NativeFunction (
		Module.findExportByName ( null, 'class_copyMethodList' ),
		'pointer',
		[ 'pointer', 'pointer' ]
	);

	var objc_getMetaClass = new NativeFunction (
		Module.findExportByName ( null, 'objc_getMetaClass' ),
		'pointer',
		[ 'pointer' ]
	);

	var method_getName = new NativeFunction (
		Module.findExportByName ( null, 'method_getName' ),
		'pointer',
		[ 'pointer' ]
	);

	var free = new NativeFunction ( Module.findExportByName ( null, 'free' ), 'void', [ 'pointer' ] );

	// get objclass and metaclass
	var name = Memory.allocUtf8String ( classname );
	var objClass = objc_getClass ( name )
	var metaClass = objc_getMetaClass ( name )

	// get obj class all methods
	var size_ptr = Memory.alloc ( Process.pointerSize );
	Memory.writeUInt ( size_ptr, 0 );
	var pObjMethods = class_copyMethodList ( objClass, size_ptr );
	var count = Memory.readUInt ( size_ptr );

	var allMethods = new Array ();

	var allObjMethods = new Array ();

	// get obj class all methods name and IMP
	for ( var i = 0; i < count; i++ ) {
		var curObjMethod = new Array ();

		var pObjMethodSEL = method_getName ( pObjMethods.add ( i * Process.pointerSize ) )
		var pObjMethodName = Memory.readCString ( Memory.readPointer ( pObjMethodSEL ) )
		var objMethodIMP = Memory.readPointer ( pObjMethodSEL.add ( 2 * Process.pointerSize ) )
		// XLOG("-["+classname+ " " + pObjMethodName+"]" + ":" + objMethodIMP)
		curObjMethod.push ( pObjMethodName )
		curObjMethod.push ( objMethodIMP )
		allObjMethods.push ( curObjMethod )
	}

	var allMetaMethods = new Array ();

	// get meta class all methods name and IMP
	var pMetaMethods = class_copyMethodList ( metaClass, size_ptr );
	var count = Memory.readUInt ( size_ptr );
	for ( var i = 0; i < count; i++ ) {
		var curMetaMethod = new Array ();

		var pMetaMethodSEL = method_getName ( pMetaMethods.add ( i * Process.pointerSize ) )
		var pMetaMethodName = Memory.readCString ( Memory.readPointer ( pMetaMethodSEL ) )
		var metaMethodIMP = Memory.readPointer ( pMetaMethodSEL.add ( 2 * Process.pointerSize ) )
		//XLOG("+["+classname+ " " + pMetaMethodName+"]" + ":" + metaMethodIMP)
		curMetaMethod.push ( pMetaMethodName )
		curMetaMethod.push ( metaMethodIMP )
		allMetaMethods.push ( curMetaMethod )
	}

	allMethods.push ( allObjMethods )
	allMethods.push ( allMetaMethods )

	free ( pObjMethods );
	free ( pMetaMethods );

	return allMethods;
}

function get_info_form_address ( address ) {

	// int dladdr(const void *, Dl_info *);

	//typedef struct dl_info {
	//        const char      *dli_fname;     /* Pathname of shared object */
	//        void            *dli_fbase;     /* Base address of shared object */
	//        const char      *dli_sname;     /* Name of nearest symbol */
	//        void            *dli_saddr;     /* Address of nearest symbol */
	//} Dl_info;

	var dladdr = new NativeFunction (
		Module.findExportByName ( null, 'dladdr' ),
		'int',
		[ 'pointer', 'pointer' ]
	);

	var dl_info = Memory.alloc ( Process.pointerSize * 4 );

	dladdr ( ptr ( address ), dl_info )

	var dli_fname = Memory.readCString ( Memory.readPointer ( dl_info ) )
	var dli_fbase = Memory.readPointer ( dl_info.add ( Process.pointerSize ) )
	var dli_sname = Memory.readCString ( Memory.readPointer ( dl_info.add ( Process.pointerSize * 2 ) ) )
	var dli_saddr = Memory.readPointer ( dl_info.add ( Process.pointerSize * 3 ) )

	//XLOG("dli_fname:"+dli_fname)
	//XLOG("dli_fbase:"+dli_fbase)
	//XLOG("dli_sname:"+dli_sname)
	//XLOG("dli_saddr:"+dli_saddr)

	var addrInfo = new Array ();

	addrInfo.push ( dli_fname );
	addrInfo.push ( dli_fbase );
	addrInfo.push ( dli_sname );
	addrInfo.push ( dli_saddr );

	//XLOG(addrInfo)
	return addrInfo;
}


function find_symbol_from_address ( modulePath, addr ) {
	var frameAddr = addr

	var theDis = 0xffffffffffffffff;
	var tmpDis = 0;
	var theClass = "None"
	var theMethodName = "None"
	var theMethodType = "-"
	var theMethodIMP = 0

	var allClassInfo = {}

	var allClass = get_all_objc_class ( modulePath );

	for ( var i = 0, len = allClass.length; i < len; i++ ) {
		var mInfo = get_all_class_methods ( allClass[ i ] );
		var curClassName = allClass[ i ]

		var objms = mInfo[ 0 ];
		for ( var j = 0, olen = objms.length; j < olen; j++ ) {
			var mname = objms[ j ][ 0 ]
			var mIMP = objms[ j ][ 1 ]
			if ( frameAddr >= mIMP ) {
				var tmpDis = frameAddr - mIMP
				if ( tmpDis < theDis ) {
					theDis = tmpDis
					theClass = curClassName
					theMethodName = mname
					theMethodIMP = mIMP
					theMethodType = "-"
				}
			}
		}

		var metams = mInfo[ 1 ];
		for ( var k = 0, mlen = metams.length; k < mlen; k++ ) {
			var mname = metams[ k ][ 0 ]
			var mIMP = metams[ k ][ 1 ]
			if ( frameAddr >= mIMP ) {
				var tmpDis = frameAddr - mIMP
				if ( tmpDis < theDis ) {
					theDis = tmpDis
					theClass = curClassName
					theMethodName = mname
					theMethodIMP = mIMP
					theMethodType = "+"
				}
			}
		}
	}

	var symbol = theMethodType + "[" + theClass + " " + theMethodName + "]"

	if ( symbol.indexOf ( ".cxx" ) != -1 ) {
		symbol = "maybe C function?"
	}

	// if distance > 3000, maybe a c function
	if ( theDis > 3000 ) {
		symbol = "maybe C function? symbol:" + symbol
	}

	return symbol;
}

function backtrace ( onlyMainModule = true ) {
	XLOG ( "================================================xCallStackSymbols==========================================" )

	function getExeFileName ( modulePath ) {
		modulePath += ""
		return modulePath.split ( "/" ).pop ()
	}

	var mainPath = ObjC.classes.NSBundle.mainBundle ().executablePath ().UTF8String ();

	var threadClass = ObjC.classes.NSThread
	var symbols = threadClass[ "+ callStackSymbols" ] ()
	var addrs = threadClass[ "+ callStackReturnAddresses" ] ()
	var count = addrs[ "- count" ] ();

	for ( var i = 0, len = count; i < len; i++ ) {

		var curAddr = addrs[ "- objectAtIndex:" ] ( i )[ "- integerValue" ] ();
		var info = get_info_form_address ( curAddr );
		// skip frida call stack
		if ( !info[ 0 ] ) {
			continue;
		}

		var dl_symbol = info[ 2 ] + ""
		var curModulePath = info[ 0 ] + ""

		var fileAddr = curAddr - get_image_vm_slide ( curModulePath );

		if ( onlyMainModule ) {
			if ( curModulePath == mainPath ) {
				var symbol = find_symbol_from_address ( curModulePath, curAddr );
			} else {
				var symbol = info[ 2 ];
			}
		} else {
			if ( ( !info[ 2 ] || dl_symbol.indexOf ( "redacted" ) != -1 ) && curModulePath.indexOf ( "libdyld.dylib" ) == -1 ) {
				var symbol = find_symbol_from_address ( curModulePath, curAddr );
			} else {
				var symbol = info[ 2 ];
			}
		}

		XLOG ( format ( i, 4 ) + format ( getExeFileName ( info[ 0 ] ), 20 ) + "mem:" + format ( ptr ( curAddr ), 13 ) + "file:" + format ( ptr ( fileAddr ), 13 ) + format ( symbol, 80 ) )
	}
	XLOG ( "==============================================================================================================" )
	return;
}

function xbacktrace ( context ) {
	XLOG ( "================================================xbacktrace==========================================" )

	function getExeFileName ( modulePath ) {
		modulePath += ""
		return modulePath.split ( "/" ).pop ()
	}

	var mainPath = ObjC.classes.NSBundle.mainBundle ().executablePath ().UTF8String ();
	var mainModuleName = getExeFileName ( mainPath )

	var backtrace = Thread.backtrace ( context, Backtracer.ACCURATE ).map ( DebugSymbol.fromAddress )
	for ( var i = 0; i < backtrace.length; i++ ) {
		var curStackFrame = backtrace[ i ] + ''
		var curSym = curStackFrame.split ( "!" )[ 1 ]
		var curAddr = curStackFrame.split ( "!" )[ 0 ].split ( " " )[ 0 ]
		var curModuleName = curStackFrame.split ( "!" )[ 0 ].split ( " " )[ 1 ]

		var info = get_info_form_address ( curAddr );
		// skip frida call stack
		if ( !info[ 0 ] ) {
			continue;
		}

		var dl_symbol = info[ 2 ] + ""
		var curModulePath = info[ 0 ] + ""

		var fileAddr = curAddr - get_image_vm_slide ( curModulePath );

		// is the image in app dir?
		if ( curModulePath.indexOf ( mainModuleName ) != -1 ) {
			curSym = find_symbol_from_address ( curModulePath, curAddr );
		}
		XLOG ( format ( i, 4 ) + format ( getExeFileName ( curModulePath ), 20 ) + "mem:" + format ( ptr ( curAddr ), 13 ) + "file:" + format ( ptr ( fileAddr ), 13 ) + format ( curSym, 80 ) )
	}
	XLOG ( "==============================================================================================================" )
	return

}

function my_backtrace () {
	console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
					.map(DebugSymbol.fromAddress).join('\n') + '\n');
}


/**
 * demangle native method name
 */
function demangle(name) {

	function popName(str) {
		/* The name is in the format <length><str> */
	
		let isLast = false;
		let namestr = "";
		let rlen = 0;
		const ostr = str;
		let isEntity = false;
	
		while (!isLast) {
	
		/* This is used for decoding names inside complex namespaces
		   Whenever we find an 'N' preceding a number, it's a prefix/namespace
		*/
		isLast = str[0] != "N";
	
		/* St means std:: in the mangled string 
		   This std:: check is for inside the name, not outside, 
		   unlike the one in the demangle function
		 */
		if (str.substr(1, 2) === "St") {
			namestr = namestr.concat("std::");
			str = str.replace("St", "");
			rlen++;
		}
	
		/* This is used for us to know we'll find an E in the end of this name
		   The E marks the final of our name
		*/
		isEntity = isEntity || !isLast;
	
		if (!isLast)
			str = str.substr(1);
	
		const res = /(\d*)/.exec(str);
	
		const len = parseInt(res[0], 10);
	
		rlen += res[0].length + len;
		
		const strstart = str.substr(res[0].length);
		namestr = namestr.concat(strstart.substr(0, len));
	
		if (!isLast) namestr = namestr.concat("::");
		str = strstart.substr(len);
		}
	
		if (isEntity)
		rlen += 2; // Take out the "E", the entity end mark
	
		return {name: namestr, str: ostr.substr(rlen)};
	}
	
	function popChar(str) {
		return {ch: str[0], str: str.slice(1)};
	}

    /* Check if the name passed is a IA64 ABI mangled name */
    function isMangled(name) {
		return name.startsWith("_Z");
    }

    function internal_demangle(name) {

		if (!isMangled(name)) return name;

		/* Encoding is the part between the _Z (the "mangling mark") and the dot, that prefix
		a vendor specific suffix. That suffix will not be treated here yet */
		const encoding = name.substr(2,
						(name.indexOf('.') < 0) ? undefined : name.indexOf('.')-2);


		let fname = popName(encoding);
		let functionname = fname.name;
		let types = [];

		let template_count = 0;
		let template_types = [];

		// Process the types
		let str = fname.str;
		
		while (str.length > 0) {
			let process = popChar(str);

			/* The type info

			isBase -> is the type the built-in one in the mangler, represented with few letters?
			typeStr: the type name
			templateType: type info for the current template.

			The others are self descriptive
			*/
			let typeInfo = {isBase: true, typeStr: "", isConst: false, numPtr: 0,
					isRValueRef: false, isRef: false, isRestrict: false,
					templateStart: false, templateEnd: false,
					isVolatile: false, templateType: null};

			/* Check if we have a qualifier (like const, ptr, ref... )*/
			var doQualifier = true;

			while (doQualifier) {
			switch (process.ch) {
			case 'R': typeInfo.isRef = true; process = popChar(process.str); break;
			case 'O': typeInfo.isRValueRef = true; process = popChar(process.str); break;
			case 'r': typeInfo.isRestrict = true; process = popChar(process.str); break;
			case 'V': typeInfo.isVolatile = true; process = popChar(process.str); break;
			case 'K': typeInfo.isConst = true; process = popChar(process.str); break;
			case 'P': typeInfo.numPtr++; process = popChar(process.str); break;
			default: doQualifier = false;
			}
			}

			/* Get the type code. Process it */
			switch (process.ch) {
			case 'v': typeInfo.typeStr = "void"; break;
			case 'w': typeInfo.typeStr = "wchar_t"; break;
			case 'b': typeInfo.typeStr = "bool"; break;
			case 'c': typeInfo.typeStr = "char"; break;
			case 'a': typeInfo.typeStr = "signed char"; break;
			case 'h': typeInfo.typeStr = "unsigned char"; break;
			case 's': typeInfo.typeStr = "short"; break;
			case 't': typeInfo.typeStr = "unsigned short"; break;
			case 'i': typeInfo.typeStr = "int"; break;
			case 'S':
			/* Abbreviated std:: types */
			process = popChar(process.str);

			switch (process.ch) {
			case 't': {
				// It's a custom type name
				const tname = popName(process.str);
				typeInfo.typeStr = "std::".concat(tname.name);
				process.str = tname.str;
				break;
			}
			case 'a': typeInfo.typeStr = "std::allocator"; break;
			case 'b': typeInfo.typeStr = "std::basic_string"; break;
			case 's': typeInfo.typeStr = "std::basic_string<char, std::char_traits<char>, std::allocator<char>>"; break;
			case 'i': typeInfo.typeStr = "std::basic_istream<char, std::char_traits<char>>"; break;
			case 'o': typeInfo.typeStr = "std::basic_ostream<char, std::char_traits<char>>"; break;
			case 'd': typeInfo.typeStr = "std::basic_iostream<char, std::char_traits<char>>"; break;
			default:
				process.str = process.ch.concat(process.str);
				break;
			}
			
			break;
			
			case 'I':
			// Template open bracket (<)
			types[types.length-1].templateStart = true;
			template_types.push(types[types.length-1]);
			template_count++;
			
			break;
			case 'E':
			// Template closing bracket (>)
			if ((template_count <= 0)) {
				str = process.str;
				continue;
			}
			
			typeInfo.templateEnd = true;

			template_count--;
			typeInfo.templateType = template_types[template_count];
			template_types = template_types.slice(0, -1);
			
			break;
					
			case 'j': typeInfo.typeStr = "unsigned int"; break;
			case 'l': typeInfo.typeStr = "long int"; break;
			case 'm': typeInfo.typeStr = "unsigned long int"; break;
			case 'x': typeInfo.typeStr = "long long int"; break;
			case 'y': typeInfo.typeStr = "unsigned long long int"; break;
			case 'n': typeInfo.typeStr = "__int128"; break;
			case 'o': typeInfo.typeStr = "unsigned __int128"; break;
			case 'f': typeInfo.typeStr = "float"; break;
			case 'd': typeInfo.typeStr = "double"; break;
			case 'e': typeInfo.typeStr = "long double"; break;
			case 'g': typeInfo.typeStr = "__float128"; break;
			case 'z': typeInfo.typeStr = "..."; break;

			/* No type code. We have a type name instead */
			default: {
			if (!isNaN(parseInt(process.ch, 10)) || process.ch == "N") {

				// It's a custom type name
				const tname = popName(process.ch.concat(process.str));
				typeInfo.typeStr = typeInfo.typeStr.concat(tname.name);
				process.str = tname.str;
			}

			} break;
			}


			types.push(typeInfo);
			str = process.str;
		}

		/* Create the string representation of the type */
		const typelist = types.map((t) => {
			let typestr = "";
			if (t.isConst) typestr = typestr.concat("const ");
			if (t.isVolatile) typestr = typestr.concat("volatile ");
			
			typestr = typestr.concat(t.typeStr);

			if (t.templateStart) typestr = typestr.concat("<");
			if (t.templateEnd) typestr = typestr.concat(">");

			if (!t.templateStart) {
			if (t.isRef) typestr = typestr.concat("&");
			if (t.isRValueRef) typestr = typestr.concat("&&");
			for (let i = 0; i < t.numPtr; i++) typestr = typestr.concat("*");
			if (t.isRestrict) typestr = typestr.concat(" __restrict");
			}
			
			if (t.templateType) {		
			if (t.templateType.isRef) typestr = typestr.concat("&");
			if (t.templateType.isRValueRef) typestr = typestr.concat("&&");
			for (let i = 0; i < t.templateType.numPtr; i++) typestr = typestr.concat("*");
			}
			
			return typestr;
		});

		/* Those replaces are an stupid shortcut to fix templates and make it fast
		Without that, we would need to complicate the code

		What it does is remove the commas where we would have the angle brackets
		for the templates
		*/
		
		return functionname.concat("(" + typelist.join(', ') + ")").replace(/<, /g, "<")
			.replace(/<, /g, "<").replace(/, >/g, ">").replace(/, </g, "<");
    }

	return internal_demangle(name);
}


/**
 * show a ios alert box
 */
function ios_alert ( title, content ) {
    var UIAlertController = ObjC.classes.UIAlertController;
    var UIAlertAction = ObjC.classes.UIAlertAction;
    var UIApplication = ObjC.classes.UIApplication;
    var handler = new ObjC.Block({ retType: 'void', argTypes: ['object'], implementation: function () {} });

    ObjC.schedule(ObjC.mainQueue, function () {
        var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(title, content, 1);
        var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
        alert.addAction_(defaultAction);
        // Instead of using `ObjC.choose()` and looking for UIViewController instances on the heap, we have direct access through UIApplication:
        UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
    })
}


function memAddress(memBase, idaBase, idaAddr) {
    var offset = ptr(idaAddr).sub(idaBase);
    var result = ptr(memBase).add(offset);
    return result;
}

function idaAddress(memBase, idaBase, memAddr) {
    var offset = ptr(memAddr).sub(memBase);
    var result = ptr(idaBase).add(offset);
    return result;
}

function modify_implementation(class_name, method_name, functions) {
    try {
      var methodObj = ObjC.classes[class_name][method_name]
      var old_implementation = methodObj.implementation;

      methodObj.implementation = ObjC.implement(methodObj, function () {
        var args = [].slice.call(arguments); // modifying Arguments object into array

        if(typeof functions['arguments'] === 'function') {
          functions['arguments'](args);
        }

        var result = old_implementation.apply(null, args);

        if(typeof functions['result'] === 'function') {
          result = functions['result'](result);
        }

        return result;
      });
    } catch (err) {
      console.log('[!] Error while hooking ' + class_name + ' [' + method_name + ']', err);
    }
}


// dylib中已经实现的打印调用堆栈的方法
const ReverseUtil = ObjC.classes.ReverseUtil;
// const PrintCallStack = ReverseUtil['+ PrintCallStack'];
// const PrintCallStack = function () { ReverseUtil['+ PrintCallStack'].implementation.apply(null, []); }
const PrintCallStack = function () { ReverseUtil.PrintCallStack(); }


/*
 * To observe a single class by name:
 *     observeClass('NSString');
 *
 * To dynamically resolve methods to observe (see ApiResolver):
 *     observeSomething('*[* *Password:*]');
 */

var ISA_MASK = ptr ( '0x0000000ffffffff8' );
var ISA_MAGIC_MASK = ptr ( '0x000003f000000001' );
var ISA_MAGIC_VALUE = ptr ( '0x000001a000000001' );

function observeSomething ( pattern ) {
	var resolver = new ApiResolver ( 'objc' );
	var things = resolver.enumerateMatchesSync ( pattern );
	things.forEach ( function ( thing ) {
		observeMethod ( thing.address, '', thing.name );
	} );
}

function observeClass ( name ) {
	var k = ObjC.classes[ name ];
	if ( !k ) {
		console.log ( "observeClass: ", name, " not found." );
		return;
	}
	k.$ownMethods.forEach ( function ( m ) {
		observeMethod ( k[ m ].implementation, name, m );
	} );
	console.log ( "observeClass: ", name, " ok." );
}

function observeMethod ( impl, name, m ) {
	console.log ( 'Observing ' + name + ' ' + m );
	Interceptor.attach ( impl, {
		onEnter: function ( a ) {
			this.log = [];
			this.log.push ( '(' + a[ 0 ] + ') ' + name + ' ' + m );
			if ( m.indexOf ( ':' ) !== -1 ) {
				var params = m.split ( ':' );
				params[ 0 ] = params[ 0 ].split ( ' ' )[ 1 ];
				for ( var i = 0; i < params.length - 1; i++ ) {
					if ( isObjC ( a[ 2 + i ] ) ) {
						const theObj = new ObjC.Object ( a[ 2 + i ] );
						this.log.push ( params[ i ] + ': ' + theObj.toString () + ' (' + theObj.$className + ')' );
					} else {
						this.log.push ( params[ i ] + ': ' + a[ 2 + i ].toString () );
					}
				}
			}

			this.log.push ( Thread.backtrace ( this.context, Backtracer.ACCURATE )
				.map ( DebugSymbol.fromAddress ).join ( "\n" ) );
		},

		onLeave: function ( r ) {
			if ( isObjC ( r ) ) {
				this.log.push ( 'RET: ' + new ObjC.Object ( r ).toString () );
			} else {
				this.log.push ( 'RET: ' + r.toString () );
			}

			console.log ( this.log.join ( '\n' ) + '\n' );
		}
	} );
}

function isObjC ( p ) {
	var klass = getObjCClassPtr ( p );
	return !klass.isNull ();
}

function getObjCClassPtr ( p ) {
	/*
	 * Loosely based on:
	 * https://blog.timac.org/2016/1124-testing-if-an-arbitrary-pointer-is-a-valid-objective-c-object/
	 */

	if ( !isReadable ( p ) ) {
		return NULL;
	}
	var isa = p.readPointer ();
	var classP = isa;
	if ( classP.and ( ISA_MAGIC_MASK ).equals ( ISA_MAGIC_VALUE ) ) {
		classP = isa.and ( ISA_MASK );
	}
	if ( isReadable ( classP ) ) {
		return classP;
	}
	return NULL;
}

function isReadable ( p ) {
	try {
		p.readU8 ();
		return true;
	} catch ( e ) {
		return false;
	}
}


/*
 * To find out who the function at 0x1234 calls the next time it is called:
 *   start(ptr('0x1234'))
 *
 * Or to ask the same question about one or more Objective-C methods, whichever is called first:
 *   start('-[LicenseManager *]')
 *
 * Or any exported function named open:
 *   start('exports:*!open*')
 */
var listeners = [];
var activated = false;

function start ( target ) {
	stop ();

	if ( typeof target === 'string' ) {
		var pattern = target;

		var resolver = new ApiResolver ( ( pattern.indexOf ( ' ' ) === -1 ) ? 'module' : 'objc' );
		var matches = resolver.enumerateMatchesSync ( pattern );
		if ( matches.length === 0 ) {
			throw new Error ( 'No matching methods found' );
		}

		matches.forEach ( function ( match ) {
			stalkMethod ( match.name, match.address );
		} );
	} else {
		stalkMethod ( target.toString (), target );
	}
}

function stop () {
	listeners.forEach ( function ( listener ) {
		listener.detach ();
	} );
	listeners = [];
	activated = false;
}

function stalkMethod ( name, impl ) {
	console.log ( 'Stalking next call to ' + name );

	var listener = Interceptor.attach ( impl, {
		onEnter: function ( args ) {
			if ( activated ) {
				return;
			}
			activated = true;

			var targets = {};
			this.targets = targets;

			console.log ( '\n\nStalker activated: ' + name );
			Stalker.follow ( {
				events: {
					call: true
				},
				onCallSummary: function ( summary ) {
					Object.keys ( summary ).forEach ( function ( target ) {
						var count = summary[ target ];
						targets[ target ] = ( targets[ target ] || 0 ) + count;
					} );
				}
			} );
		},
		onLeave: function ( reval ) {
			var targets = this.targets;
			if ( targets === undefined ) {
				return;
			}

			Stalker.unfollow ();
			console.log ( 'Stalker deactivated: ' + name );

			printSummary ( targets );
		}
	} );
	listeners.push ( listener );
}

function printSummary ( targets ) {
	var items = [];
	var total = 0;
	Object.keys ( targets ).forEach ( function ( target ) {
		var name = DebugSymbol.fromAddress ( ptr ( target ) ).toString ();
		var count = targets[ target ];
		var tokens = name.split ( ' ', 2 ).map ( function ( t ) {
			return t.toLowerCase ();
		} );
		items.push ( [ name, count, tokens ] );
		total += count;
	} );
	items.sort ( function ( a, b ) {
		var tokensA = a[ 2 ];
		var tokensB = b[ 2 ];
		if ( tokensA.length === tokensB.length ) {
			return tokensA[ tokensA.length - 1 ].localeCompare ( tokensB[ tokensB.length - 1 ] );
		} else if ( tokensA.length > tokensB.length ) {
			return -1;
		} else {
			return 1;
		}
	} );

	if ( items.length > 0 ) {
		console.log ( '' );
		console.log ( 'COUNT\tNAME' );
		console.log ( '-----\t----' );
		items.forEach ( function ( item ) {
			var name = item[ 0 ];
			var count = item[ 1 ];
			console.log ( count + '\t' + name );
		} );
	}

	console.log ( '' );
	console.log ( 'Unique functions called: ' + items.length );
	console.log ( '   Total function calls: ' + total );
	console.log ( '' );
}


/**
 * listen all -[* initWithURL*] **
 */
function listen_all_initwithurl () {
	var resolver = new ApiResolver ( 'objc' );

	resolver.enumerateMatches ( '-[* initWithURL*]', {
		onMatch: function ( match ) {
			Interceptor.attach ( ptr ( match.address ), {
				onEnter: function ( args ) {
					var url = new ObjC.Object ( args[ 2 ] );

					// if (url.toString().indexOf("license.key") == -1) {
					// 	return
					// }

					console.log ( 'New req to ' + url.toString () + ':\n' +
						Thread.backtrace ( this.context, Backtracer.ACCURATE )
							.map ( DebugSymbol.fromAddress ).join ( '\n' ) + '\n' );

					// PrintCallStack ();

					// backtrace ();
					// xbacktrace (this.content);

					// ios_alert("Frida", "got url -> license.key");
				}
			} );
			console.log ( '[i] ' + match.name + ' hooked.' );
		},
		onComplete: function () { /* MUST NOT be omitted */
		}
	} );
}
// listen_all_initwithurl ();


/**
 * listen_for_requests
 */
function listen_for_requests () {
	console.log ( 'Listening For Requests...' );

	function toHexString ( byteArray ) {
		return Array.from ( byteArray, function ( byte ) {
			return ( '0' + ( byte & 0xFF ).toString ( 16 ) ).slice ( -2 );
		} ).join ( '' )
	}

	if ( ObjC.available ) {

		try {

			var className = "NSURLRequest";
			var funcName = "- initWithURL:";

			var hook = eval ( 'ObjC.classes.' + className + '["' + funcName + '"]' );

			Interceptor.attach ( hook.implementation, {


				onEnter: function ( args ) {
					console.log ( 'NSURLRequest with URL: ' + ObjC.Object ( args[ 2 ] ) );
				},

			} );

		} catch ( error ) {
			console.log ( "[!] Exception: " + error.message );
		}

		try {

			var className = "SRWebSocket";//"LGSRWebSocket";
			var funcName = "- send:";

			var hook = eval ( 'ObjC.classes.' + className + '["' + funcName + '"]' );


			Interceptor.attach ( hook.implementation, {


				onEnter: function ( args ) {
					var socketURL = ObjC.Object ( args[ 0 ] ).url ().absoluteString ().toString ();
					var data = ObjC.Object ( args[ 2 ] );

					console.log ( 'LGSRWebSocket (' + ObjC.Object ( args[ 0 ] ) + ') ---> ' + socketURL );
					console.log ( 'Data: ' + data );

					for ( var i = 0; i < data.length (); i++ ) {
						console.log ( data.characterAtIndex_ ( i ).toString ( 16 ) + ' --> ' + data.characterAtIndex_ ( i ).toString () );
					}
				},

			} );

		} catch ( error ) {
			console.log ( "[!] Exception: " + error.message );
		}

		try {

			var className = "SRWebSocket";//"LGSRWebSocket";
			var funcName = "- _handleMessage:";

			var hook = eval ( 'ObjC.classes.' + className + '["' + funcName + '"]' );

			Interceptor.attach ( hook.implementation, {


				onEnter: function ( args ) {
					console.log ( 'LGSRWebSocket received: ' + ObjC.Object ( args[ 2 ] ) );
				},

			} );

		} catch ( error ) {
			console.log ( "[!] Exception: " + error.message );
		}

	} else {

		console.log ( "Objective-C Runtime is not available!" );

	}
}


/**
 * dump Objective C classes hierarchy
 * root = hierarchy()
 * console.log(JSON.stringify(root, null, 4))
 */
function dump_Objective_C_classes_hierarchy () {
	function hierarchy () {
		var objc_copyClassNamesForImage = new NativeFunction ( Module.findExportByName (
			null, 'objc_copyClassNamesForImage' ), 'pointer', [ 'pointer', 'pointer' ] )
		var free = new NativeFunction ( Module.findExportByName ( null, 'free' ), 'void', [ 'pointer' ] )
		var classes = new Array ( count )
		var p = Memory.alloc ( Process.pointerSize )
		Memory.writeUInt ( p, 0 )
		var path = ObjC.classes.NSBundle.mainBundle ().executablePath ().UTF8String ()
		var pPath = Memory.allocUtf8String ( path )
		var pClasses = objc_copyClassNamesForImage ( pPath, p )
		var count = Memory.readUInt ( p )
		for ( var i = 0; i < count; i++ ) {
			var pClassName = Memory.readPointer ( pClasses.add ( i * Process.pointerSize ) )
			classes[ i ] = Memory.readUtf8String ( pClassName )
		}
		free ( pClasses )

		var tree = {}
		classes.forEach ( function ( name ) {
			var clazz = ObjC.classes[ name ]
			var chain = [ name ]
			while ( clazz = clazz.$superClass )
				chain.unshift ( clazz.$className )

			var node = tree
			chain.forEach ( function ( clazz ) {
				node[ clazz ] = node[ clazz ] || {}
				node = node[ clazz ]
			} )
		} )
		return tree
	}

	let root = hierarchy ()
	console.log ( JSON.stringify ( root, null, 4 ) )
}


function hook_all_oc_methods () {

	function classname_filter ( class_name ) {
		// fuzzy
		if ( class_name.startsWith ( "FIR" ) ) {
			return false
		}
		if ( class_name.startsWith ( "GDTC" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PodsDummy_" ) ) {
			return false
		}
		// if ( class_name.startsWith ( "AppsFlyer" ) ) {
		// 	return false
		// }
		if ( class_name.startsWith ( "Wacom" ) ) {
			return false
		}
		// if ( class_name.startsWith ( "APM" ) ) {
		// 	return false
		// }
		if ( class_name.startsWith ( "AFSDK" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyPanGesture" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyTouchKey" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyProgressiOS" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyButtonCreator" ) ) {
			return false
		}
		// if ( class_name.startsWith ( "PWThread" ) ) {
		// 	return false
		// }
		if ( class_name.startsWith ( "PWLegacyTouch" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyLongPressGesture" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyReceipt" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyWacomStylus" ) ) {
			return false
		}
		// if ( class_name.startsWith ( "PWLegacyFloatingView" ) ) {
		// 	return false
		// }
		if ( class_name.startsWith ( "PWLegacyDesktopView" ) ) {
			return false
		}
		if ( class_name.startsWith ( "PWLegacyText" ) ) {
			return false
		}

		// detail class name
		switch ( class_name ) {
			case "ConvDataSource":
			case "APMConditionalUserProperty":
			case "APMInAppPurchaseItem":
			case "FBLPromise":
			case "TouchManager":
			case "PalmRejectionManager":
			case "RejectionZone":
			case "TrackedTouch":
			case "PWUITouch":
			case "PWLegacyClassPtrObject":
			case "PWLegacyTextSelectionRectiOS":
			case "PWLegacyWindowiOS":
			case "PWLegacyFileProviderModaliOS":
			case "PWLegacyImagePicker":
			// case "PWLegacyPaymentTransactionObserveriOS":
			case "VELegacyReceiptCacheiOS":
			// case "VELegacyPurchaseiOS":
			case "PWLegacyURLSessionCocoa":
			// case "PWLegacyApplicationiOS":
			case "PWLegacyDesktopWindowiOS":
			case "PWLegacyDesktopViewiOS":
			// case "PWLegacyDesktopViewControlleriOS":
			case "PWLegacyWindowViewControlleriOS":
			case "PWLegacyRootViewControlleriOS":
			// case "PWLegacyApplicationDelegateiOS":
			case "PWLegacyNotificationViewControlleriOS":
			case "PWLegacyNotificationiOS":
			case "PWLegacyCursoriOS":
			case "PWLegacyDesktopViewToolTipiOS":
			case "PWLegacySecurityScopedURLManageriOS":
			case "PWApplicationDelegateInvalidiOS":
			case "PWLegacyGLViewiOS":
			case "LeWacomStylusService":
			case "GULMutableDictionary":
			case "PWThreadController":
				return false
			default:
				return true
		}
	}

	function classname_filter_inv ( class_name ) {
		// detail class name
		switch ( class_name ) {
			case "APMInAppPurchaseItem":
			case "APMInAppPurchaseProductCache":
			case "APMInAppPurchaseTransactionReporter":
			// case "PWLegacyFileProviderModaliOS":
				return true
			default:
				return false
		}
	}

	function method_filter ( class_name, method_name ) {
		// detail class name
		switch ( class_name + "::" + method_name ) {
			case "VELegacyPaymentTransactionObserveriOS::defaultObserver":
			case "PWLegacyPaymentTransactionObserveriOS::sharedInstance":
			case "APMInAppPurchaseProductCache::sharedInstance":
			case "PWLegacyApplicationDelegateiOS::desktopViewController":
			case class_name + "::sharedInstance":
			case class_name + "::defaultObserver":
			case class_name + "::.cxx_destruct":
			case "APMMeasurement::" + method_name:
			case "APMMonitor::" + method_name:
				return false
			default:
				return true
		}
	}

	function find_all_methods ( obj ) {
		return Object.getOwnPropertyNames ( obj ).filter ( function ( property ) {
			return typeof obj[ property ] == "function";
		} ).join ( '\n' );
	}

	function all_properties ( obj ) {
		return Object.getOwnPropertyNames ( obj );
	}

	function get_timestamp () {
		var today = new Date ();
		var timestamp = today.getFullYear () + '-' + ( today.getMonth () + 1 ) + '-' + today.getDate () + ' ' + today.getHours () + ":" + today.getMinutes () + ":" + today.getSeconds () + ":" + today.getMilliseconds ();
		return timestamp;
	}

	function hook_class_method ( class_name, method_name ) {
		var hook = eval ( 'ObjC.classes.' + class_name + '["' + method_name + '"]' );
		Interceptor.attach ( hook.implementation, {
			onEnter: function ( args ) {
				console.log ( "[*] [" + get_timestamp () + " ] Detected call to: " + class_name + " -> " + method_name );
				// console.log(args)
				// if (args && args.length != 0) {
				//     for (let i = 0; i < args.length; i++) {
				//         let ocObj = ObjC.Object(args[i]);
				//         console.log("\t arg" + (i + 1).toString(), ocObj, "type:", typeof (ocObj));
				//     }
				// }
				// this.className = ObjC.Object(args[0]).toString();
				// this.methodName = ObjC.selectorAsString(args[1]);
				// logMessage(this.className + ":" + this.methodName);
				// logMessage("method: " + ObjC.Object(args[2]).toString());
				// try {
				//     logMessage("args: " + ObjC.Object(args[3]).toString());
				// } catch (error) {}
				// backtrace ( true );
				// xbacktrace ( this.context );
				// console.log ( "\n\n" );
			},
			onLeave: function ( retval ) {},
		} );
	}

	function hook_class_method_2 ( name, impl ) {
		Interceptor.attach ( impl, {
			onEnter: function ( args ) {
				// console.log ( "[*] [" + get_timestamp () + " ] Detected call to: " + name );
				console.log ( "[*] Detected call to: " + name );
				// console.log ();
				// console.log(args)
				// if (args && args.length != 0) {
				//     for (let i = 0; i < args.length; i++) {
				//         let ocObj = ObjC.Object(args[i]);
				//         console.log("\t arg" + (i + 1).toString(), ocObj, "type:", typeof (ocObj));
				//     }
				// }
				// this.className = ObjC.Object(args[0]).toString();
				// this.methodName = ObjC.selectorAsString(args[1]);
				// logMessage(this.className + ":" + this.methodName);
				// logMessage("method: " + ObjC.Object(args[2]).toString());

				// console.log("param:"+args[2]+" type:"+typeof args[2]);
				// console.log(new ObjC.Object(args[2]).toString());
				// console.log("end onEnter() callback");

				// print caller
				// console.log("Caller: " + DebugSymbol.fromAddress(this.returnAddress));
				// console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
				// 	.map(DebugSymbol.fromAddress).join('\n') + '\n');
				// PrintCallStack ();

				// print args
				// if (name.indexOf(":") !== -1) {
				// 	console.log();
				// 	var par = name.split(":");
				// 	par[0] = par[0].split(" ")[1];
				// 	for (var i = 0; i < par.length - 1; i++)
				// 		printArg(par[i] + ": ", args[i + 2]);
				// }

				// backtrace ( true );
				// xbacktrace ( this.context );
				// console.log ( "\n" );
			},
			onLeave: function ( retval ) {
				// console.log("return", ObjC.Object(retval).toString());
				// console.log("[+] Returning (type:"+typeof retval+",value:"+retval+")");
				// var retvalPointer = ptr(retval);
				// if (retvalPointer.isNull()) {
				// 	return;
				// }
				// var str = new ObjC.Object(ptr(retval)).toString();
				// console.log('[+] Returning (' + new ObjC.Object(retval).$className + ') -> ', str);
				// return retval;

				// print retval
				// printArg("\nretval: ", retval);
			},
		} );
	}

	function run_hook_all_methods_of_classes_app_only () {
		console.log ( "[*] Started: Hook all methods of all app only classes" );
		var free = new NativeFunction ( Module.findExportByName ( null, 'free' ), 'void', [ 'pointer' ] )
		var copyClassNamesForImage = new NativeFunction ( Module.findExportByName ( null, 'objc_copyClassNamesForImage' ), 'pointer', [ 'pointer', 'pointer' ] )
		var p = Memory.alloc ( Process.pointerSize )
		Memory.writeUInt ( p, 0 )
		var path = ObjC.classes.NSBundle.mainBundle ().executablePath ().UTF8String ()
		var pPath = Memory.allocUtf8String ( path )
		var pClasses = copyClassNamesForImage ( pPath, p )
		var count = Memory.readUInt ( p )
		var classesArray = new Array ( count )
		for ( var i = 0; i < count; i++ ) {
			var pClassName = Memory.readPointer ( pClasses.add ( i * Process.pointerSize ) )
			classesArray[ i ] = Memory.readUtf8String ( pClassName )
			var className = classesArray[ i ]
			if ( !classname_filter ( className ) ) {
			// if ( !classname_filter_inv ( className ) ) {
				console.log("[*] Skip: ", className);
				continue
			}
			if ( ObjC.classes.hasOwnProperty ( className ) ) {
				console.log ( "[+] Class: " + className );

				// console.log(find_all_methods(ObjC.classes[className]));

				var pattern = "-[" + className + " *]";
				// var resolver = new ApiResolver ( ( pattern.indexOf ( ' ' ) === -1 ) ? 'module' : 'objc' );
				var resolver = new ApiResolver ( 'objc' );
				var matches = resolver.enumerateMatchesSync ( pattern );
				if ( matches.length !== 0 ) {
					matches.forEach ( function ( match ) {
						hook_class_method_2 ( match.name, match.address );
					} );
				}
				pattern = "+[" + className + " *]";
				matches = resolver.enumerateMatchesSync ( pattern );
				if ( matches.length !== 0 ) {
					matches.forEach ( function ( match ) {
						hook_class_method_2 ( match.name, match.address );
					} );
				}
				

				//var methods = ObjC.classes[className].$methods;
				// var methods = ObjC.classes[ className ].$ownMethods;
				// for ( var j = 0; j < methods.length; j++ ) {
				// 	try {
				// 		var className2 = className;
				// 		var funcName2 = methods[ j ];

				// 		if ( !method_filter ( className2, funcName2 ) ) {
				// 			// console.log("[*] Skip: ", className);
				// 			continue
				// 		}

				// 		console.log("[-] Method: " + methods[j]);
				// 		hook_class_method ( className2, funcName2 );
				// 		// console.log("[*] [" + get_timestamp() + "] Hooking successful: " + className2 + " -> " + funcName2);
				// 	} catch ( err ) {
				// 		console.log ( "[*] [" + get_timestamp () + "] Hooking Error: " + err.message );
				// 	}
				// }
			}
		}
		free ( pClasses )
		console.log ( "[*] Completed: Hook all methods of all app only classes" );
	}

	function hook_all_methods_of_classes_app_only () {
		setImmediate ( run_hook_all_methods_of_classes_app_only )
	}

	hook_all_methods_of_classes_app_only ()
}
// hook_all_oc_methods ()


function printArg(desc, arg) {
	try {
		console.log(desc + ObjC.Object(arg));
	}
	catch(err) {
		console.log(desc + arg);
	}
}


/**
 * hook native C method
 */
const MAIN_BASE_ADDRESS = Module.findBaseAddress("CLIP STUDIO PAINT");

function attach_c_method ( method_name, on_enter, on_leave, trace_on_enter=false ) {
	Interceptor.attach(ptr(Module.getExportByName(null, method_name)), {
		onEnter: function(args) {
			on_enter && on_enter(args)
			trace_on_enter && backtrace();
		},
		onLeave: function(retval) {
			on_leave && on_leave(retval)
		}
	});
}

function attach_c_method_address ( address_offset, on_enter, on_leave, trace_on_enter=false ) {
	const ao = eval("'" + address_offset + "'");
	console.log("attach at", memAddress(MAIN_BASE_ADDRESS, '0x0', ao));
	Interceptor.attach(memAddress(MAIN_BASE_ADDRESS, '0x0', ao), {
		onEnter: function(args) {
			on_enter && on_enter(args)
			trace_on_enter && backtrace();
		},
		onLeave: function(retval) {
			on_leave && on_leave(retval)
		}
	});
}


// 输出已加载的模块
// console.log(JSON.stringify(Process.enumerateModules()));

console.log("CLIP STUDIO PAINT", MAIN_BASE_ADDRESS);
console.log("Process.codeSigningPolicy", Process.codeSigningPolicy);

// Process.setExceptionHandler ( function (details) {
// 	console.log("Ops! target crash");
// 	console.log(JSON.stringify(details));
// 	my_backtrace();
// 	backtrace();
// 	PrintCallStack();
// } );


// observeClass( "VELegacyPaymentTransactionObserveriOS" );
// observeClass( "VELegacyPurchaseiOS" );
// observeClass( "PWLegacyPurchaseViewControlleriOS" );
// observeClass( "PWLegacyFileProviderModaliOS" );

// start('-[VELegacyPaymentTransactionObserveriOS *]')
// start('+[PWLegacyFileProviderModaliOS *]')
// start('-[PWLegacyFileProviderModaliOS *]')

// var address = Module.findExportByName ( null, 'AudioServicesPlaySystemSound' )
// var play_sound = new NativeFunction ( address, 'void', [ 'int' ] )
// play_sound ( 1007 )

// attach_c_method('_ZNK12Planeswalker6Venser21VESerialVariationList17IsVersionupSerialERKNS0_18VESerialHeaderBaseE', null, null, true);
// attach_c_method('_ZNK12Planeswalker6Venser18VEActivationEngine13VerifyLicenseEv', null, null, true);

// // 内部调用一堆验证序列号的可疑函数
// attach_c_method_address(0x0047d31e0, null, null, true);
// // read serial相关
// attach_c_method_address(0x00474c208, null, null, true);
// // 测这个方法是读取license相关的方法 int (int, int)
// attach_c_method_address(0x004755e24, null, null, true);
// // 验证的核心逻辑
// attach_c_method_address(0x0047d3614, null, null, true);
// // -[PWLegacyPurchaseViewControlleriOS requestDidFinish:]
// attach_c_method_address(0x0044f5120, null, null, true);
//  Planeswalker::Legacy::PWLegacyPurchase::IsPurchased()
// attach_c_method_address(0x0000000002b5e16c, null, null, true);

// Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker4Urza4MainEv')), {
// 	onEnter: function(args) {
// 		console.log("Planeswalker::Urza::Main() onEnter");
// 	},
// });

// Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker4Urza13URApplication12ReceiveEventERNS_7PWEventE')), {
// 	onEnter: function(args) {
// 		console.log("Planeswalker::Urza::URApplication::ReceiveEvent(Planeswalker::PWEvent&) onEnter");
// 	},
// });

Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker4Urza13URApplication20InitializeActivationEv')), {
	onEnter: function(args) {
		console.log("\nPlaneswalker::Urza::URApplication::InitializeActivation() onEnter\n");
	},
	onLeave: function(retval) {
		console.log("Planeswalker::Urza::URApplication::InitializeActivation() Return value-> (value:"+retval+")");
	}
});

Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker6Venser18VEActivationEngine4InitEPS1_RKN5boost10shared_ptrINS0_30VEActivationApplicationDefineIEEE')), {
	onEnter: function(args) {
		console.log("\nPlaneswalker::Venser::VEActivationEngine::Init() onEnter\n");
	},
	onLeave: function(retval) {
		console.log("Planeswalker::Venser::VEActivationEngine::Init() Return value-> (value:"+retval+")");
	}
});

Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker6Legacy16PWLegacyPurchase11IsPurchasedEv')), {
	onEnter: function(args) {
		console.log("\nPlaneswalker::Legacy::PWLegacyPurchase::IsPurchased() onEnter\n");
	},
	onLeave: function(retval) {
		console.log("Planeswalker::Legacy::PWLegacyPurchase::IsPurchased() Return value-> (value:"+retval+")");
	}
});


Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker6Venser18VEActivationEngine15FirstActivationEj')), {
	onEnter: function(args) {
		console.log("Planeswalker::Venser::VEActivationEngine::FirstActivation(unsigned int) onEnter");
		// my_backtrace();
	},
	onLeave: function(retval) {
		console.log("Planeswalker::Venser::VEActivationEngine::FirstActivation(unsigned int) Return value-> (value:"+retval+")");
	}
});

// Interceptor.attach(ptr(Module.getExportByName(null, '_ZNK12Planeswalker6Venser18VEActivationEngine13VerifyLicenseEv')), {
// 	onEnter: function(args) {},
// 	onLeave: function(retval) {
// 		console.log("Planeswalker::Venser::VEActivationEngine::VerifyLicense() Return value-> (value:"+retval+")");
// 	}
// });

Interceptor.attach(ptr(Module.getExportByName(null, '_ZNK12Planeswalker6Venser18VEActivationEngine12VerifySerialERKNS0_8VESerialE')), {
	onEnter: function(args) {},
	onLeave: function(retval) {
		console.log("Planeswalker::Venser::VEActivationEngine::VerifySerial(Planeswalker::Venser::VESerial const&) Return value-> (value:"+retval+")");
	}
});

// Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker6Venser18VEActivationEngine22CheckLicenseActivationEv')), {
// 	onEnter: function(args) {},
// 	onLeave: function(retval) {
// 		console.log("Planeswalker::Venser::VEActivationEngine::CheckLicenseActivation() Return value-> (value:"+retval+")");
// 	}
// });

// Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker6Venser18VEActivationEngine12ShowPurchaseEv')), {
// 	onEnter: function(args) {
// 		console.log("Planeswalker::Venser::VEActivationEngine::ShowPurchase() onEnter");
// 	},
// 	onLeave: function(retval) {
// 		console.log("Planeswalker::Venser::VEActivationEngine::ShowPurchase() Return value-> (value:"+retval+")");
// 	}
// });

Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker12PWIceUtility35IsExistGetLicenseDiscriminationFileEv')), {
	onEnter: function(args) {
		console.log("Planeswalker::PWIceUtility::IsExistGetLicenseDiscriminationFile() onEnter ");
	},
	onLeave: function(retval) {
		console.log("Planeswalker::PWIceUtility::IsExistGetLicenseDiscriminationFile() Return value-> (value:"+retval+")");
	}
});

Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker12PWIceUtility35IsExistShowBootQADiscriminationFileEv')), {
	onEnter: function(args) {
		console.log("Planeswalker::PWIceUtility::IsExistShowBootQADiscriminationFile() onEnter ");
	},
	onLeave: function(retval) {
		console.log("Planeswalker::PWIceUtility::IsExistShowBootQADiscriminationFile() Return value-> (value:"+retval+")");
	}
});

Interceptor.attach(ptr(Module.getExportByName(null, '_ZN12Planeswalker6Venser18VEActivationEngine20GetLicenseActivationEv')), {
	onEnter: function(args) {
		console.log("Planeswalker::Venser::VEActivationEngine::GetLicenseActivation() onEnter ");
	},
	onLeave: function(retval) {
		console.log("Planeswalker::Venser::VEActivationEngine::GetLicenseActivation() Return value-> (value:"+retval+")");
	}
});