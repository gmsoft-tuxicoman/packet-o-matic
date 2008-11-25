/// <reference path="minilib.js">
/// <reference path="xml.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
/// <reference path="pom.js">
/// <reference path="dialog.js">
pom.targets = function() { };
pom.targets._avail = [];
pom.targets._loaded = {};
pom.targets.onload = function() {
	this._list_avail();
	this._list_loaded();
	this._target_dialog = $("target_dialog");
	this._control_type = $("target_gui_type");
	this._control_mode = $("target_gui_mode");
	this._control_params = $("target_params");

	this._list_ul = $("target_list");
	this._cur_targets = {};
	this._inp_descr = $("target_descr");
	Element.hide(this._target_dialog);
};
pom.targets._update_target = function(rule_id, target_id, descr, name, started) {
	this._cur_targets[rule_id][target_id].started = started;
	var img = $("target_enabled_" + rule_id + "_" + target_id);
	img.enabled = started;
	if (started) {
		img.src = "icons/arrows_green.gif";
		img.title = "Target enabled, click to disable";
	}
	else {
		img.src = "icons/arrows_red.gif";
		img.title = "Target disabled, click to enable";
	}
	var span;
	if (name) {
		span = $("target_span_" + rule_id + "_" + target_id);
		span.innerHTML = "";
		span.appendChild($T(name));
	}
	if (descr) {
		span = $("target_spandesc_" + rule_id + "_" + target_id);
		span.innerHTML = "";
		span.appendChild($T(descr));
	}
};
pom.targets.set_description = function(rule_id, target_id, descr) {
	pom.tools.make_request("target.setDescription", pom.tools.create_params("int", rule_id, "int", target_id, "string", descr), pom.tools._action_done.bind(pom.tools, "add target descr"));
}
pom.targets.toggle = function(rule_id, target_id) {
	var img = $("target_enabled_" + rule_id + "_" + target_id);
	if (img.enabled)
		this.stop(rule_id, target_id);
	else
		this.start(rule_id, target_id);
}
pom.targets._load_rule_back = function(rule_id, child_node, req) {
	req = firefox_fix(req);
	var target_array = pom.array.cast(pom.xml.make_element_from_req(req));
	var x;
	var kids = target_array.get_children();
	var target_struct;
	var tr;
	var td;
	this._cur_targets[rule_id] = {};
	this.remove_targets(rule_id);
	if (!kids.length) {
		tr = $E("TR");
		tr.id = "target_tr_" + rule_id;
		td = $E("TD");
		tr.appendChild(td);
		td = $E("TD");
		td.style.paddingLeft = "5px";
		td.innerHTML = "<img src='icons/line.gif'><img src='icons/join.gif'>No Targets";
		tr.appendChild(td);
		tr.appendChild($E("td"));
		this._add_after(child_node, tr);
	}
	for (x = 0; x < kids.length; x++) {

		target_struct = pom.struct.cast(kids[x]);
		var name = target_struct.get_child("name").get_value();
		var started = target_struct.get_child("started").get_value();
		var mode = target_struct.get_child("mode").get_value();
		var target_id = target_struct.get_child("uid").get_value();
		var params = target_struct.get_child("params");
		var descr = target_struct.get_child("description").get_value();
		this._cur_targets[rule_id][target_id] = { name: name, started: started, mode: mode, params: params, descr: descr };
		tr = $E("TR");
		td = $E("TD");
		td.style.textAlign = "right";
		tr.id = "target_tr_" + rule_id + "_" + target_id;
		td.appendChild(pom.tools.create_icon_button("edit.gif", "Edit Target", this.gui_edit.bind(this, rule_id, target_id)));
		td.appendChild(pom.tools.create_icon_button("delete.gif", "Remove Target", this.remove.bind(this, rule_id, target_id)));
		var img;
		img = $E("img");
		img.onclick = this.toggle.bind(this, rule_id, target_id);
		img.id = "target_enabled_" + rule_id + "_" + target_id;
		img.style.cursor = "pointer";
		td.appendChild(img);
		tr.appendChild(td);
		td = $E("TD");
		td.style.paddingLeft = "5px";
		img = $E("img");
		img.src = "icons/line.gif";
		td.appendChild(img);
		img = $E("img");
		img.src = "icons/join.gif";
		td.appendChild(img);
		span = $E("SPAN");
		span.id = "target_span_" + rule_id + "_" + target_id;
		td.appendChild(span);
		tr.appendChild(td);
		td = $E("TD");
		span = $E("SPAN");
		span.id = "target_spandesc_" + rule_id + "_" + target_id;
		td.appendChild(span);
		tr.appendChild(td);
		this._add_after(child_node, tr);
		this._update_target(rule_id, target_id, descr, name, started);
	}
}

pom.targets.list_show = function(rule_id,child_node) {
	if (!rule_id)
		return;
	this.load_rule(rule_id,child_node);

}
pom.targets._toggle_back = function(rule_id, target_id, is_enabled, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault((is_enabled) ? "Start Target" : "Stop Target", req.responseXML))
		return;
	this._update_target(rule_id,target_id, "", "", is_enabled);
};
pom.targets._remove_back = function(rule_id,target_id) {
	var li = $("target_tr_" + target_id);
	Element.remove(li);
};
pom.targets.remove = function(rule_id, target_id) {
	if (!rule_id || !target_id)
		return fatal("Must select a rule and target to remove it");
	var args = pom.tools.create_params("int", rule_id, "int", target_id);
	pom.tools.make_request("target.remove", args, this._remove_back.bind(this, rule_id, target_id));
};
pom.targets.stop = function(rule_id, target_id) {
	if (!rule_id || ! target_id)
		return fatal("Must select a rule and target to stop it");
	var args = pom.tools.create_params("int", rule_id,"int",target_id);
	pom.tools.make_request("target.stop", args, this._toggle_back.bind(this, rule_id, target_id, false));
};
pom.targets.start = function(rule_id, target_id) {
	if (!rule_id || !target_id)
		return fatal("Must select a rule and target to start it");
	var args = pom.tools.create_params("int", rule_id, "int", target_id);
	pom.tools.make_request("target.start", args, this._toggle_back.bind(this, rule_id, target_id, true));
};
pom.targets.gui_stop = function() {
	this._gui_hide();
	this.stop(this._cur_target);
};
pom.targets.gui_start = function() {
	this._gui_hide();
	this.start(this._cur_target);
};
pom.targets.gui_remove = function() {
	this._gui_hide();
	this.remove(this._cur_target);
};
pom.targets._gui_hide = function() {
	Element.hide(this._target_dialog);
	$$("body")[0].appendChild(this._target_dialog);
	pom.dialog.done();
};
pom.targets.gui_edit = function(rule_id, target_id) {
	if (!rule_id || !target_id)
		return fatal("Must select a rule and a target to edit it");
	this._cur_rule_id = rule_id;
	this._cur_target = target_id;
	Element.show(this._target_dialog);
	Element.hide(this._control_type);
	Element.hide(this._control_mode);
	Element.hide(this._control_params);
	var target_obj = this._cur_targets[rule_id][target_id];
	pom.dialog.create(this._target_dialog);
	$("target_type").value = target_obj.name;
	this._type_changed();
	$("target_mode").value = target_obj.mode;
	this._mode_changed();
	this._inp_descr.value = target_obj.descr;
	var param_arr = pom.array.cast(target_obj.params);
	var kids = param_arr.get_children();
	var x;
	var param_struct;
	for (x = 0; x < kids.length; x++) {
		param_struct = pom.struct.cast(kids[x]);
		var name = param_struct.get_child("name").get_value();
		var val = param_struct.get_child("value").get_value();
		$("target_param_" + name).value = val;
	}
	pom.dialog.re_center();
};
pom.targets.gui_add = function(rule_id) {
	if (!rule_id)
		return fatal("Must select a rule to add a target to it");
	this._cur_rule_id = rule_id;
	this._cur_target = "";
	this._inp_descr.value = "";
	$("target_type").selectedIndex = 0;
	Element.show(this._target_dialog);
	Element.show(this._control_type);
	Element.hide(this._control_mode);
	Element.hide(this._control_params);
	pom.dialog.create(this._target_dialog);
};
pom.targets._type_add_back = function(rule_id, target_id, descr, mode, params_arr, req) {
	if (req) {
		req = firefox_fix(req);
		if (pom.tools.check_fault("target set type", req.responseXML))
			return;
		target_id = pom.xml.make_element_from_req(req).get_value();
	}
	pom.tools.make_request("target.setMode", pom.tools.create_params("int", rule_id, "int", target_id, "string", mode), this._mode_save_back.bind(this, rule_id, target_id, params_arr));
	if (descr)
		this.set_description(rule_id, target_id, descr);
};
pom.targets.remove_targets = function(rule_id) {
	var child_node = $("rule_tr_" + rule_id);
	var next_node = child_node.nextSibling;
	while (next_node) {
		if (next_node.id.indexOf("target_tr_" + rule_id) == -1)
			break;
		Element.remove(next_node);
		next_node = child_node.nextSibling;
	}
};
pom.targets._add_after = function(cur_node, new_node) {
	var parent = cur_node.parentNode;
	var next_child = cur_node.nextSibling;
	new_node.className = cur_node.className;
	if (next_child)
		parent.insertBefore(new_node, next_child);
	else
		parent.appendChild(new_node);
};
pom.targets._mode_save_back = function(rule_id, target_id, params, req) {
	if (req) {
		req = firefox_fix(req);
		if (pom.tools.check_fault("target set mode", req.responseXML))
			return;
	}
	var x;
	for (x = 0; x < params.length; x++)
		this.set_parameter(rule_id, target_id, params[x][0], params[x][1]);
	var child_node = $("rule_tr_" + rule_id);
	this.list_show(rule_id,child_node);
};

pom.targets.gui_save = function() {
	var mode = $F("target_mode");
	var type = $F("target_type");
	var descr = this._inp_descr.value;
	if (!mode || !type)
		return alert("You must select a target mode and target type before saving a target");
	var x;
	var val;
	var params_arr = [];
	for (x in this._params) {
		val = $F("target_param_" + x);
		params_arr.push([x, val]);
	}

	if (this._cur_target)
		this._type_add_back(this._cur_rule_id, this._cur_target, descr, mode, params_arr);
	else {
		var func = this._type_add_back.bind(this, this._cur_rule_id, this._cur_target, descr, mode, params_arr);
		var params = pom.tools.create_params("int", this._cur_rule_id, "string", type);
		pom.tools.make_request("target.add", params, func);
	}
	this._gui_hide();
};
pom.targets.gui_cancel = function() {
	this._gui_hide();
};
pom.targets._list_avail_back = function(req) {
	req = firefox_fix(req);
	var arr = pom.array.cast(pom.xml.make_element_from_req(req));
	var kids = arr.get_children();
	for (var x = 0; x < kids.length; x++)
		this._avail.push(kids[x].get_value());
	pom.targets._setup_target_form();		
};
pom.targets._list_loaded_back = function(on_done,req) {
	req = firefox_fix(req);
	var arr = pom.array.cast(pom.xml.make_element_from_req(req));
	var kids = arr.get_children();
	var target_struct;
	var x;
	for (x = 0; x < kids.length; x++) {
		target_struct = pom.struct.cast(kids[x]);
		var name = target_struct.get_child("name").get_value();
		var modes = target_struct.get_child("modes");
		this._loaded[name] = modes;
	}
	if (on_done)
		on_done();
};
pom.targets._list_loaded = function(on_done) {
	pom.tools.make_request("target.listLoaded", "", this._list_loaded_back.bind(this,on_done));
};
pom.targets._list_avail = function() {
	pom.tools.make_request("target.listAvail", "", this._list_avail_back.bind(this));
};
pom.targets._mode_changed = function() {
	this._mode = $F("target_mode");
	$("target_params").innerHTML = "";
	if (!this._mode)
		return;
	var x;
	var name;
	var param_arr = pom.array.cast(this._modes[this._mode]);
	kids = param_arr.get_children();
	var ul = $("target_params");
	var param_struct;
	this._params = {};
	for (x = 0; x < kids.length; x++) {
		var li = $E("LI");
		param_struct = pom.struct.cast(kids[x]);
		name = param_struct.get_child("name").get_value();
		var descr = param_struct.get_child("descr").get_value();
		var defval = param_struct.get_child("defval").get_value();
		li.appendChild($T(name + " -- " + descr + "(" + defval + ")"));
		var inp = $E("input");
		inp.id = "target_param_" + name;
		inp.value = defval;
		li.appendChild(inp);
		ul.appendChild(li);
		this._params[name] = defval;
	}
	Element.show(this._control_params);
	pom.dialog.re_center();
};
pom.targets._type_changed = function() {
	this._type = $F("target_type");
	var select = $("target_mode");
	while (select.childNodes.length)
		select.removeChild(select.firstChild);
	$("target_params").innerHTML = "";
	if (!this._type) {
		Element.hide(this._control_mode);
		pom.dialog.re_center();
		return;
	}

	if (!this._loaded[this._type] || this._loaded[this._type] == 1) {
		this.load_target(this._type, this._type_changed.bind(this));
		return;
	}


	var modes = pom.array.cast(this._loaded[this._type]);
	var kids = modes.get_children();
	if (!kids || kids.length < 1) {
		Element.hide(this._control_mode);
		pom.dialog.re_center();
		return;
	}
	var x;
	this._modes = {};
	for (x = 0; x < kids.length; x++) {
		var mode_info = pom.struct.cast(kids[x]);
		var name = mode_info.get_child("name").get_value();
		var desc = mode_info.get_child("descr").get_value();
		var option = $E("option");
		option.value = name;
		option.innerHTML = name + " -- " + desc;
		select.appendChild(option);
		this._modes[name] = mode_info.get_child("params");
	}
	Element.show(this._control_mode);
	select.selectedIndex = 0;
	this._mode_changed();
	select.onchange = pom.targets._mode_changed.bind(this);
};
pom.targets._setup_target_form = function() {
	var select = $("target_mode");
	while (select.childNodes.length)
		select.removeChild(select.firstChild);
	$("target_params").innerHTML = "";
	this._inp_descr.value = "";
	select = $("target_type");
	while (select.childNodes.length)
		select.removeChild(select.firstChild);
	var x;
	var elem = $E("option");
	elem.value = "";
	elem.innerHTML = " -- Pick one -- ";
	select.appendChild(elem);
	for (x = 0; x < this._avail.length; x++) {

		elem = $E("OPTION");
		elem.value = this._avail[x];
		elem.innerHTML = this._avail[x];
		select.appendChild(elem);
	}
	select.onchange = pom.targets._type_changed.bind(this);
};
pom.targets.set_parameter = function(rule_id,target_id,name, value) {
	var args = pom.tools.create_params("int",rule_id,"int",target_id,"string", name, "string", value);
	pom.tools.make_request("target.setParameter", args, pom.tools._action_done.bind(pom.tools, "set type"));
};

pom.targets.load_rule = function(rule_id,child_node) {
	var params = pom.tools.create_params("int", rule_id);
	pom.tools.make_request("target.get", params, this._load_rule_back.bind(this,rule_id,child_node));

};
pom.targets.load_all = function() {
	var x;
	this._loaded['null'] = 1;
	for (x = 0; x < this._avail.length; x++) {
		var name = this._avail[x];
		if (this._loaded[name])
			continue;
		this._loaded[name] = 1;
		this.load_target(name);
	}
	setTimeout(this._list_loaded.bind(this), 1000);
};
pom.targets._load_target_back = function(name, on_done, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("Loading module: " + name, req.responseXML))
		return;
	if (on_done)
		this._list_loaded(on_done);
};
pom.targets.load_target = function(name, on_done) {
	var params = pom.tools.create_params("string", name);
	pom.tools.make_request("target.load", params, this._load_target_back.bind(this,name,on_done) );
};
