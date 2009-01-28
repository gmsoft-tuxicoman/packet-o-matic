/// <reference path="minilib.js">
/// <reference path="xml.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
/// <reference path="dialog.js">

pom.input = function() { };
pom.input._avail = [];
pom.input._input_types = {};
pom.input._input_modes = {};
pom.input._input_params = {};
Class.register_class("pom.input", pom.input);
pom.input.onload = function() {
	this._div = $("input_dialog");
	Element.hide(this._div);
	this.list_avail();
	this.list_loaded(this.load_current_config.bind(this));
};
pom.input.gui_config = function() {
	Element.show(this._div);
	pom.dialog.create(this._div);
};
pom.input._list_avail_back = function(req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("input list aval", req.responseXML))
		return;
	var arr = pom.array.cast(pom.xml.make_element_from_req(req));
	var kids = arr.get_children();
	this._avail = [];
	for (var x = 0; x < kids.length; x++)
		this._avail.push(kids[x].get_value());
	var Arr = [];
	for (x = 0; x < this._avail.length; x++)
		Arr.push(this._avail[x]);
	var div = this._create_input("input_type", "", "select", Arr, "", this._input_selected.bind(this));
	$("content").appendChild(div);

};
pom.input.list_avail = function() {
	pom.tools.make_request("input.listAvail", "", this._list_avail_back.bind(this));
};
pom.input._load_back = function(name, on_done, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("input Loading module: " + name, req.responseXML))
		return;
	if (on_done)
		this.list_loaded(on_done);
};
pom.input.load = function(name, on_done) {
	var params = pom.tools.create_params("string", name);
	pom.tools.make_request("input.load", params, this._load_back.bind(this, name, on_done));
};
pom.input._type_save_back = function(mode, params_arr, req) {
	if (req) {
		req = firefox_fix(req);
		if (pom.tools.check_fault("input set type", req.responseXML))
			return;
	}
	pom.tools.make_request("input.setMode", pom.tools.create_params("string", mode), this._mode_save_back.bind(this, params_arr));
};
pom.input._mode_save_back = function(params, req) {
	if (req) {
		req = firefox_fix(req);
		if (pom.tools.check_fault("input set mode", req.responseXML))
			return;
	}
	var x;
	for (x = 0; x < params.length; x++)
		this.set_parameter(params[x][0], params[x][1]);
};
pom.input._gui_config_save = function() {
	var type = $F("inp_input_type");
	var mode = $F("inp_input_mode");
	if (!type || !mode) {
		alert("You must supply an input type and input mode before saving input");
		return;
	}
	var params_arr = [];
	for (x in this._input_params) {
		var val = $F("inp_" + x);
		params_arr.push([x, val]);
	}
	if (type != this._cur_type)
		pom.tools.make_request("input.setType", pom.tools.create_params("string", type), this._type_save_back.bind(this, mode, params_arr));
	else if (mode != this._cur_mode)
		pom.input._type_save_back(mode, params_arr);
	else
		pom.input._mode_save_back(params_arr);

	Element.hide(this._div);
	$$("body")[0].appendChild(this._div);
	pom.dialog.done();
};
pom.input._gui_config_no_save = function() {
	Element.hide(this._div);
	$$("body")[0].appendChild(this._div);
	pom.dialog.done();
};
pom.input.start = function() {
	this._started = true;
	pom.tools.make_request("input.start", null, pom.tools._action_done.bind(pom.tools, "input start"));
	this._toggle_update();
};
pom.input.stop = function() {
	this._started = false;
	pom.tools.make_request("input.stop", null, pom.tools._action_done.bind(pom.tools, "input stop"));
	this._toggle_update();
};
pom.input.set_type = function(type) {
	var args = pom.tools.create_params("string", type);
	pom.tools.make_request("input.setType", args, pom.tools._action_done.bind(pom.tools, "set type"));
};
pom.input.set_mode = function(mode) {
	var args = pom.tools.create_params("string", mode);
	pom.tools.make_request("input.setMode", args, pom.tools._action_done.bind(pom.tools, "set type"));
};
pom.input.set_parameter = function(name, value) {
	var args = pom.tools.create_params("string", name, "string", value);
	pom.tools.make_request("input.setParameter", args, pom.tools._action_done.bind(pom.tools, "set type"));
};
pom.input._toggle_update = function() {
	var button = $("input_control");
	if (this._started)
		button.innerHTML = "Stop Input";
	else
		button.innerHTML = "Start Input";

};
pom.input.toggle = function() {
	if (this._started)
		this.stop();
	else
		this.start();
};
pom.input.load_current_config = function() {
	pom.tools.make_request("input.get", "", pom.input._load_current_config_back.bind(this));
};
function firefox_fix(req) {
	if (pom.tools.is_IE())
		return req;
	var text = req.responseText.replace(/[\r\n]/g, "");
	var parser = new DOMParser();
	var ret = parser.parseFromString(text, "text/xml");
	var obj = {};
	obj.responseXML = ret;
	obj.reponseText = text;
	return obj;
	
};
pom.input._load_current_config_back = function(req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("input loading config", req.responseXML))
		return;
	this._cur_config = pom.struct.cast(pom.xml.make_element_from_req(req));
	if (this._cur_config.get_type() != "struct")
		return;
	var type = this._cur_config.get_child("type");
	if (!type)
		return;
	type = type.get_value();
	this._cur_type = type;
	if (!this._input_types[type]) {
		this.load(type,this._ready_load_config.bind(this));

	}
	else
		this._ready_load_config();
};
pom.input._create_input = function(name, desc, type, values, def_value, onChange, unit) {
	/// <summary>Creates a input of various types</summary>
	/// <param name="name" type="String"></param>
	/// <param name="desc" type="String"></param>
	/// <param name="type" type="String"></param>
	/// <param name="values" type="Array"></param>
	/// <param name="def_value" type="String"></param>
	/// <param name="onChange" type="Function"></param>
	/// <param name="unit" type="String"></param>
	var div = $E("div");
	var inp;
	var opt;
	var x;
	var def_str = "";
	if (def_value)
		def_str = "(" + def_value + ")";
	if (desc)
		desc = " -- " + desc;
	else
		desc = "";
	div.innerHTML = name + desc + def_str + ": ";
	if (!type || type == "text") {
		inp = $E("input");
		if (values)
			inp.value = values;
		else if (def_value)
			inp.value = def_value;
	}
	else if (type == "select") {
		inp = $E("select");
		opt = $E("option");
		inp.appendChild(opt);
		for (x = 0; x < values.length; x++) {
			opt = $E("option");
			opt.innerHTML = values[x];
			var splitted = values[x].split(" -- ");
			opt.value = splitted[0];
			inp.appendChild(opt);
		}
	}
	inp.id = "inp_" + name;
	inp.onchange = onChange;
	div.appendChild(inp);
	if (unit)
		div.appendChild($T(unit));
	var child = $E("div");
	child.id = "inp_" + name + "_child";
	div.appendChild(child);
	return div;

};
pom.input.list_loaded = function(on_done) {
	pom.tools.make_request("input.listLoaded", null, this._list_loaded_back.bind(this,on_done));
};

pom.input._list_loaded_back = function(on_done, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("listInputs", req.responseXML))
		return;
	var elem = pom.xml.make_element_from_req(req);
	var opts = pom.array.cast(elem);
	var kids = opts.get_children();
	var x;
	var struct;
	var val;
	this._input_types = {};
	for (x = 0; x < kids.length; x++) {
		struct = pom.struct.cast(kids[x]);
		val = struct.get_child("name");
		this._input_types[val.get_value()] = struct.get_child("modes");
	}
	if (on_done)
		on_done();
};
pom.input._input_selected = function() {
	var type = $F("inp_input_type");
	$("inp_input_type_child").innerHTML = "";
	if (!type)
		return pom.dialog.re_center(); ;
	var opts = pom.array.cast(this._input_types[type]);
	if (!opts || opts == 1) {
		this.load(type, this._input_selected.bind(this));
		return;
	}
	var kids = opts.get_children();
	var x;
	var struct;
	var val;
	this._input_modes = {};
	var Arr = [];
	for (x = 0; x < kids.length; x++) {
		struct = pom.struct.cast(kids[x]);
		val = struct.get_child("name");
		var desc = struct.get_child("descr");
		Arr.push(val.get_value() + " -- " + desc.get_value());
		this._input_modes[val.get_value()] = struct.get_child("params");
	}
	var div = this._create_input("input_mode", "", "select", Arr, "", this._mode_selected.bind(this));
	$("inp_input_type_child").appendChild(div);
	pom.dialog.re_center();
}
pom.input._mode_selected = function() {
	var type = $F("inp_input_mode");
	$("inp_input_mode_child").innerHTML = "";
	if (!type)
		return pom.dialog.re_center();
	var opts = pom.array.cast(this._input_modes[type]);
	var kids = opts.get_children();
	var x;
	var struct;
	var val;
	this._input_params = {};
	for (x = 0; x < kids.length; x++) {
		struct = pom.struct.cast(kids[x]);
		var name = struct.get_child("name").get_value();
		var unit = struct.get_child("unit").get_value();
		var defval = struct.get_child("defval").get_value();
		var descr = struct.get_child("descr").get_value();
		this._input_params[name] = { unit: unit, defval: defval, descr: descr };

	}
	for (x in this._input_params) {
		opts = this._input_params[x];

		var div = this._create_input(x, opts.descr, "text", "", opts.defval, null, opts.unit);
		$("inp_input_mode_child").appendChild(div);
	}
	if (type == this._cur_mode && this._cur_type == $F("inp_input_type"))
		this._ready_load_config(true);
	pom.dialog.re_center();
};
pom.input._ready_load_config = function(already_set) {
	this._cur_config = pom.struct.cast(this._cur_config);
	var type = this._cur_config.get_child("type").get_value();
	var x;
	$("inp_input_type").value = type;
	this._started = this._cur_config.get_child("running").get_value();
	this._toggle_update();
	if (!already_set)
		this._input_selected();
	var mode = this._cur_config.get_child("mode").get_value();
	this._cur_mode = mode;
	var opts = $("inp_input_mode").options;
	for (x = 0; x < opts.length; x++) {
		if (opts[x].value.indexOf(mode) == 0)
			$("inp_input_mode").value = opts[x].value;
	}
	if (!already_set)	
		this._mode_selected();
	var params = pom.array.cast(this._cur_config.get_child("parameters")).get_children();
	var struct;
	for (x = 0; x < params.length; x++) {
		struct = pom.struct.cast(params[x]);
		var name = struct.get_child("name").get_value();
		var value = struct.get_child("value").get_value();
		$("inp_" + name).value = value;
	}
};
