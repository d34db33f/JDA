//Given a Uint8Array (slice), treat it like a standard C string
//and make a JS string out of it
//Useful if you e.g. want to extract inline strings or magic byte sequences
function Uint8ArrayToString(a) {
	var ret="";
	for(var i=0;i<a.length;i++) {
		if(a[i]==0)
			break;
		ret+=String.fromCharCode(a[i]);
	}
	return ret;
}

//http://stackoverflow.com/a/10073788/1933738
//pad a string from the left
function pad(n, width, z) {
  z = z || '0';
  n = n + '';
  return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
}
//Given a Uint8Array (slice), make a hexdump string out of it
//Useful to check magic byte sequences with non readable chars
function Uint8ArrayToHexString(a) {
	var ret="";
	for(var i=0;i<a.length;i++)
		ret+=pad(a[i].toString(16),2,"0");
	return ret.toUpperCase();
}

//Log a message to the console
function conlog(msg) {
	var $con=$("#console_area pre");
	$con.html($con.html()+msg+"\n");
	$("#console").scrollTo("120%",{axis:"y"});
	console.log(msg);
}
//returns the padded hex representation of a number with given bytesize
function toHex(num,bytes) {
	var hex=num.toString(16);
	var len=bytes*2;
	return pad(hex,len,"0");
}
if(!ArrayBuffer.transfer) {
	ArrayBuffer.transfer=function(oldBuffer,newLength) {
		var ret=new ArrayBuffer(newLength);
		var ov=new Uint8Array(oldBuffer);
		var nv=new Uint8Array(ret);
		for(var i=0;i<newLength;i++)
			nv[i]=0;
		if(newLength>=oldBuffer.byteLength) {
			for(var i=0;i<oldBuffer.byteLength;i++)
				nv[i]=ov[i];
		} else {
			for(var i=0;i<newLength;i++)
				nv[i]=ov[i];
		}
		return ret;
	}
}