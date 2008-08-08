/// <reference path="minilib.js">
/// <reference path="xml.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
/// <reference path="targets.js">
/// <reference path="dialog.js">
/// <reference path="rules.js">
/// <reference path="input.js">
var first_serial_check = true;
function doload() {
	serial_check();
}
function doloadrest() {
	pom.input.onload();
	pom.rules.onload();
	pom.targets.onload();
	pom.dialog.onload();
	pom.core_params.onload();
	log_check(0);
}
function load_all_modules() {
	pom.input.load_all();
	pom.targets.load_all();
}
function _serial_changed(name) {
	switch (name) {
		case "targets":
		case "rules":
			pom.rules.load();
			break;
		case "input":
			pom.input.list_loaded(pom.input.load_current_config.bind(pom.input));
			break;
		case "core":
			pom.core_params.load();
	}
}
function _serial_watcher_back(req) {
	req = firefox_fix(req);
	if (first_serial_check) {
		first_serial_check = false;
		doloadrest();
	}
	var struct = pom.struct.cast(pom.xml.make_element_from_req(req));
	var kids = struct.get_children();
	if (!this._serials)
		this._serials = {};
	for (var x in kids) {
		if ( (this._serials[x] || this._serials[x] == "0") && this._serials[x] != kids[x].get_value())
			_serial_changed(x);
		this._serials[x] = kids[x].get_value();
	}
	setTimeout(serial_check.bind(this), 1000);
}
function serial_check()
{
	pom.tools.make_request("main.getSerial", null, _serial_watcher_back.bind(this));
}
function _log_check_back(last_id, req) {
	req = firefox_fix(req);
	var array = pom.array.cast(pom.xml.make_element_from_req(req));
	var kids = array.get_children();
	var x;
	var console_log = $("console_log");
	var ignore = (last_id == 0);
	for (x = 0; x < kids.length; x++) {
		var struct = pom.struct.cast(kids[x]);
		var file = struct.get_child("file").get_value();
		var data = struct.get_child("data").get_value();
		var id = struct.get_child("id").get_value();
		if (id > last_id)
			last_id = id;
		else
			continue;
		if (! ignore)
			console_log.innerHTML = file + ": " + data + " ID IS: " + id + "<BR>" + console_log.innerHTML;
	}
	setTimeout(log_check.bind(this, last_id), 1000);
}
function log_check(last_id) {
	pom.tools.make_request("main.getLogs", pom.tools.create_params("int", last_id), _log_check_back.bind(this, last_id));
}
function tester_back(req) {
	alert(req.responseText);
}
function tester() {
	pom.tools.make_request("core.getParameters", "", tester_back);
	//pom.tools.make_request("main.getSerial", null, tester_back);
	
}
window.onload = doload;
function fatal(msg) {
	alert(msg);
	return null;
}
