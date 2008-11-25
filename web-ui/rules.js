/// <reference path="minilib.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
/// <reference path="pom.js">
/// <reference path="dialog.js">
/// <reference path="targets.js">
pom.rules = function(){};
pom.rules._rules = new Object(); //rule id to rule_str conversion
pom.rules._rulesdescr = new Object(); //rule id to rule descr conversion
pom.rules._rules_enabled = new Object(); //rule id to boolean of if eanbled
pom.rules._rules_open = new Object();
pom.rules.onload = function() {
	this._table = $("rule_list");
	this._tbody = $("rule_list_body");
	this._prompt_dialog = $E("DIV");
	this._prompt_dialog.appendChild($T("What is the rule you want to add: "));
	this._prompt_dialog.appendChild($E("BR"));
	this._prompt_dialog.appendChild($T("Rule: "));
	this._prompt_input = $E("input");
	this._prompt_input.size = 30;
	this._prompt_dialog.appendChild(this._prompt_input);
	this._prompt_dialog.appendChild($E("BR"));
	this._prompt_dialog.appendChild($T("Descr: "));
	this._prompt_inputdesc = $E("input");
	this._prompt_inputdesc.size = 30;
	this._prompt_dialog.appendChild(this._prompt_inputdesc);
	this._prompt_dialog.appendChild($E("BR"));
	this._button_div = $E("DIV");
	this._button_div.className="button_set";
	this._prompt_dialog.appendChild(this._button_div);

	this._prompt_submit = $E("LI");
	this._prompt_submit.className="nav";
	var link = $E("A");
	link.innerHTML = "Add Rule";
	link.href = "javascript:pom.rules.prompt_prompt_add_back();";
	this._prompt_submit.appendChild(link);
	this._button_div.appendChild(this._prompt_submit);
	this._button_div.style.textAlign="center";

	this._prompt_submit2 = $E("LI");
	this._prompt_submit2.className="nav";
	link = $E("A");
	link.innerHTML = "Edit Rule";
	link.href = "javascript:pom.rules.prompt_change_back();";
	this._prompt_submit2.appendChild(link);
	this._button_div.appendChild(this._prompt_submit2);
	this._button_div.appendChild($T(" "));

	this._prompt_cancel = $E("LI");
	this._prompt_cancel.className="nav";
	link = $E("A");
	link.innerHTML = "Cancel";
	link.href = "javascript:pom.rules.prompt_add_back_cancel();";
	this._prompt_cancel.appendChild(link);
	this._button_div.appendChild(this._prompt_cancel);

	pom.rules.load();	
};
pom.rules.add = function(rule_str,rule_descr) {
	var args = pom.tools.create_params("string", rule_str);
	pom.tools.make_request("rules.add", args, this._add_back.bind(this, rule_str, rule_descr) );
};
pom.rules.prompt_add = function() {
	this._prompt_input.value = "";
	this._prompt_inputdesc.value = "";
	Element.hide(this._prompt_submit2);
	Element.show(this._prompt_submit);
	pom.dialog.create(this._prompt_dialog);
};
pom.rules.prompt_add_back_cancel = function() {
	Element.remove(this._prompt_dialog);
	pom.dialog.done();
}
pom.rules.prompt_prompt_add_back = function() {
	Element.remove(this._prompt_dialog);
	pom.dialog.done();
	var rule_str = this._prompt_input.value;
	var rule_desc = this._prompt_inputdesc.value;
	this._prompt_input.value = "";
	this._prompt_inputdesc.value = "";
	if (!rule_str) {
		alert("Sorry you must enter a rule str to add a rule");
		return;
	}
	this.add(rule_str,rule_desc);

};
pom.rules.prompt_change_back = function() {
	var rule_str = this._prompt_input.value;
	var desc_str = this._prompt_inputdesc.value;
	Element.remove(this._prompt_dialog);
	pom.dialog.done();
	if (!rule_str) {
		alert("Sorry you must enter a rule str to edit a rule");
		return;
	}
	this.set_description(this._cur_change_rule_id,desc_str);
	this.change(this._cur_change_rule_id, rule_str,desc_str);

};
pom.rules.prompt_change = function(rule_id) {
	if (!rule_id)
		return fatal("Must select a rule to disable it");
	this._prompt_input.value = this._rules[rule_id];
	this._prompt_inputdesc.value = this._rulesdescr[rule_id];
	Element.show(this._prompt_submit2);
	Element.hide(this._prompt_submit);
	pom.dialog.create(this._prompt_dialog);
	this._cur_change_rule_id = rule_id;
}
pom.rules._add_back = function(rule_str, rule_descr, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("Add/Edit Rule", req.responseXML))
		return;
	var id = pom.node.cast(pom.xml.make_element_from_req(req));

	var val = id.get_value();
	if (rule_descr)
		this.set_description(val, rule_descr);
	this._add_or_update(val, rule_str, rule_descr, this._rules_enabled[val]);

};
pom.rules.set_description = function(rule_id, rule_descr) {
	pom.tools.make_request("rules.setDescription", pom.tools.create_params("int", rule_id, "string", rule_descr), pom.tools._action_done.bind(pom.tools, "add rule descr"));
}
pom.rules._add_or_update = function(rule_id, rule_value, rule_descr, enabled) {
	if (!this._rules[rule_id])
		this._add_rule(rule_id, rule_value, rule_descr, enabled);
	else
		this._update_rule(rule_id, rule_value, rule_descr, enabled);
};
pom.rules._update_rule = function(rule_id, rule_value, rule_descr, enabled) {
	this._rules_enabled[rule_id] = enabled;
	var img = $("rule_enabled_" + rule_id);
	var span = $("rule_span_" + rule_id);
	var spandesc = $("rule_spandesc_" + rule_id);
	if (enabled)
		img.src = "icons/arrows_green.gif";
	else
		img.src = "icons/arrows_red.gif";
	if (rule_value) {
		span.innerHTML = " " + rule_value;
		spandesc.innerHTML = rule_descr;
		this._rules[rule_id] = rule_value;
		this._rulesdescr[rule_id] = rule_descr;
	}
};
pom.rules._node_toggle = function(rule_id, force_open) {
	var tree_node = $("rule_node_" + rule_id);
	if (!tree_node) {
		delete this._rules_open[rule_id];
		return;
	}
	tree_node.expanded = !tree_node.expanded;
	if (force_open)
		tree_node.expanded = force_open;
	this._rules_open[rule_id] = tree_node.expanded;
	var child_node = $("rule_tr_" + rule_id);
	if (tree_node.expanded) {
		tree_node.title = "Targets shown, click to hide";
		tree_node.src = "icons/minus.gif";
		pom.targets.remove_targets(rule_id);
		pom.targets.list_show(rule_id, child_node);
	}
	else {
		tree_node.src = "icons/plus.gif";
		tree_node.title = "Targets hidden, click to show";
		pom.targets.remove_targets(rule_id);
	}

};
pom.rules.toggle = function(rule_id) {
	if (this._rules_enabled[rule_id])
		this.disable(rule_id);
	else
		this.enable(rule_id);
}
pom.rules._add_rule = function(rule_id, rule_value, rule_descr, enabled) {
	var tr = $E("TR");
	tr.id = "rule_tr_" + rule_id;
	var td;
	td = $E("TD");
	td.vAlign = "middle";
	var img = $E("img");
	img.onclick = this.toggle.bind(this, rule_id);
	img.id = "rule_enabled_" + rule_id;
	img.style.cursor = "pointer";
	td.appendChild(pom.tools.create_icon_button("add.gif", "Add Target", pom.targets.gui_add.bind(pom.targets, rule_id)));
	td.appendChild(pom.tools.create_icon_button("edit.gif", "Edit Rule", this.prompt_change.bind(this, rule_id)));
	td.appendChild(pom.tools.create_icon_button("delete.gif", "Remove Rule", this.remove.bind(this, rule_id)));

	td.appendChild(img);
	tr.appendChild(td);
	td = $E("TD");
	var tree_node = $E("img");
	tree_node.src = "icons/plus.gif";
	tree_node.title = "Targets hidden, click to show";
	tree_node.onclick = this._node_toggle.bind(this, rule_id, false);
	tree_node.id = "rule_node_" + rule_id;
	tree_node.style.cursor = "pointer";
	tree_node.expanded = false;
	td.appendChild(tree_node);

	span = $E("SPAN");
	span.id = "rule_span_" + rule_id;
	span.className = "rule_name";

	td.appendChild(span);
	this._is_odd = !this._is_odd;
	var class_is = "even";
	if (this._is_odd) {
		class_is = "odd";
	}
	tr.className = class_is;
	td.style.paddingLeft = "5px";
	tr.appendChild(td);
	td = $E("TD");
	span = $E("SPAN");
	span.id = "rule_spandesc_" + rule_id;
	td.appendChild(span);
	td.style.paddingLeft = "10px";
	tr.appendChild(td);
	this._tbody.appendChild(tr);
	this._update_rule(rule_id, rule_value, rule_descr, enabled);
};
pom.rules.change = function(rule_id, rule_str,rule_descr) {
	if (!rule_id)
		return fatal("Must select a rule to disable it");
	var args = pom.tools.create_params("int", rule_id, "string", rule_str);
	pom.tools.make_request("rules.set", args, this._add_back.bind(this, rule_str,rule_descr));
};
pom.rules.remove = function(rule_id) {
	if (!rule_id)
		return fatal("Must select a rule to disable it");
	var args = pom.tools.create_params("int", rule_id);
	pom.tools.make_request("rules.remove", args, this._remove_back.bind(this, rule_id));
};
pom.rules._remove_back = function(rule_id, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("Remove Rule", req.responseXML))
		return;
	this._remove(rule_id);
};
pom.rules._remove = function(rule_id) {

	pom.targets.remove_targets(rule_id);
	var li = $("rule_tr_" + rule_id);
	Element.remove(li);	
	delete this._rules[rule_id];
	delete this._rules_enabled[rule_id];
};
pom.rules._toggle_back = function(rule_id, is_enabled, req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault((is_enabled) ? "Enable Rule" : "Disable Rule", req.responseXML))
		return;
	this._rules_enabled[rule_id] = is_enabled;
	var span = $("rule_span_" + rule_id);
	span.className = (is_enabled) ? "rule_enabled" : "rule_disabled";
	this._update_rule(rule_id, "","", is_enabled);
};
pom.rules.enable = function(rule_id) {
	if (!rule_id)
		return fatal("Must select a rule to disable it");
	var args = pom.tools.create_params("int", rule_id);
	pom.tools.make_request("rules.enable", args, this._toggle_back.bind(this, rule_id, true));
};
pom.rules.disable = function(rule_id) {
	if (!rule_id)
		return fatal("Must select a rule to disable it");
	var args = pom.tools.create_params("int", rule_id);
	pom.tools.make_request("rules.disable", args, this._toggle_back.bind(this, rule_id, false));
};
pom.rules.load = function() {
	var x;
	for (x in this._rules)
		this._remove(x);
	pom.tools.make_request("rules.get", "", pom.rules._load_back.bind(this));
};
pom.rules._load_back = function(req) {
	req = firefox_fix(req);
	if (pom.tools.check_fault("Load Rules", req.responseXML))
		return;
	var x;
	var elem = pom.array.cast(pom.xml.make_element_from_req(req));
	var kids = elem.get_children();
	for (x = 0; x < kids.length; x++) {
		var rule = pom.struct.cast(kids[x]);
		var rule_str = rule.get_child("rule").get_value();
		var enabled = rule.get_child("enabled").get_value();
		var descr = rule.get_child("description").get_value();
		var id = rule.get_child("uid").get_value();
		this._add_or_update(id, rule_str, descr, enabled);
	}
	for (x in this._rules_open)
		if (this._rules_open[x])
		this._node_toggle(x, true);
};
