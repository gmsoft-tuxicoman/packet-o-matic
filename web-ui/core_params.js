/// <reference path="minilib.js">
/// <reference path="xml.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
/// <reference path="dialog.js">
pom.core_params = function() { };
pom.core_params.onload = function() {
	this._core_div = $("core_dialog");
	Element.hide(this._core_div);
	this._content_div = $("core_params_list");
	this._params = {};
	this.load();
};
pom.core_params.show = function() {
	Element.show(this._core_div);
	pom.dialog.create(this._core_div);
};
pom.core_params.save = function() {
	var x;
	for (x in this._params) {
		pom.tools.make_request("core.setParameter", new pom.tools.create_params("string", x, "string", $F("core_params_" + x)), pom.tools._action_done.bind(pom.tools, "set core params"));
	}
	Element.remove(this._core_div);
	pom.dialog.done();	
};
pom.core_params.cancel = function() {
	Element.remove(this._core_div);
	pom.dialog.done();
};
pom.core_params._load_back = function(req) {
	req = firefox_fix(req);
	var arr = pom.array.cast(pom.xml.make_element_from_req(req));
	var kids = arr.get_children();
	var x;
	for (x = 0; x < kids.length; x++) {
		var struct = pom.struct.cast(kids[x]);
		var name = struct.get_child("name").get_value();
		var value = struct.get_child("value").get_value();
		var unit = struct.get_child("unit").get_value();
		this._params[name] = value;
		var div = $E("div");
		div.appendChild($T(name + ": "));
		var inp = $E("input");
		inp.id="core_params_" + name;
		div.appendChild(inp);
		inp.value = value;
		if (unit)
			div.appendChild($T(" " + unit));
		this._content_div.appendChild(div);
	}

};
pom.core_params.load = function() {
	this._params = {};
	this._content_div.innerHTML = "";
	pom.tools.make_request("core.getParameters", "", this._load_back.bind(this));
};