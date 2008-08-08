/// <reference path="minilib.js">
/// <reference path="xmlrpc.js">

pom.tools = function() { };
Class.register_class("pom.tools", pom.tools);
pom.tools.halt = function() {
	pom.tools.make_request("main.halt", null, this._action_done.bind(pom.tools, "halt"));
};
pom.tools.set_password = function(pass) {
	var args = this.create_params("string", pass);
	make_request("main.setPassword", args, this._action_done.bind(pom.tools, "set password"));
};
pom.tools.create_icon_button = function(file_name, tip, on_click) {
	/// <summary>Makes an image that has a tooltip and is clickable</summary>
	/// <param name="file_name" type="String"></param>
	/// <param name="tip" type="String"></param>
	/// <param name="on_click" type="Function"></param>
	/// <returns type="HTMLElement" />
	var img = $E("img");
	img.src = "icons/" + file_name;
	img.onclick = on_click;
	img.className = "img_button";
	img.title = tip;
	return img;
};
pom.tools.make_request = function(method, params, on_done) {
	/// <summary>Makes a request to the specified method and passes it the data in the pom parray</summary>
	/// <param name="method" type="String"></param>
	/// <param name="params" type="pom.params"></param>
	/// <param name="on_done" type="Function"></param>
	var x;
	if (!params)
		params = new pom.params();
	params = pom.params.cast(params);
	var toSend = '<?xml version="1.0"?><methodCall>  <methodName>' + method + '</methodName>' + params.to_xml() + "</methodCall>";
	var path = "/RPC2";
	var loc = "" + document.location;
	if (loc.indexOf("T:") != -1)
		path = "http://10.10.10.1/RPC2";
	network_request("POST", path, toSend, on_done);
};
pom.tools._action_done = function(name, req) {
	pom.tools.check_fault(name, req.responseXML);
};
pom.tools.check_fault = function(action, xml) {
	/// <summary>Checks for a fault in a response and alerts the user to it</summary>
	/// <param name="action" type="String">action to let the user know faulted</param>
	/// <param name="xml" type="XMLNode">XmlNode to check for the fault</param>
	/// <returns type="boolean">if faulted</returns>
	var elems = xml.getElementsByTagName("fault");
	if (!elems || !elems.length)
		return false;
	var struct = pom.struct.cast(pom.xml.make_element(elems[0].childNodes[0].childNodes[0]));
	var err = struct.get_child("faultString").get_value();
	alert("Cannot complete " + action + " due to: \r\n" + err);
	return true;
};
pom.tools.create_params = function() {
	/// <summary>Takes an unlimited number of arguments which go node_type,node_value ...</summary>
	/// <returns type="pom.params" />
	var params = new pom.params();
	var x;
	var node;
	for (x = 0; x < arguments.length; x += 2) {
		node = pom.node.create_node(arguments[x]);
		node.set_value(arguments[x + 1]);
		params.add_child(node);
	}
	return params;
};
var _is_IE = (/MSIE ((5\.5)|[6]|[7])/.test(navigator.userAgent) && navigator.platform == "Win32") == true;
pom.tools.is_IE = function() {
	/// <summary>Returns true if the browser is IE</summary>
	/// <returns type="boolean"></returns>
	return _is_IE;
}

