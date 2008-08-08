/// <reference path="minilib.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
pom.xml = function() { };
pom.xml.make_element_from_req = function(req) {
	/// <returns type="pom.node" />
	var xml = req.responseXML;
	var ret = xml.getElementsByTagName("methodResponse");
	if (!ret.length)
		return fatal("An error occured: " + req.responseText);

	var base = ret[0];
	var child = pom.xml.get_child_by_type(base, "params");
	if (!child)
		return fatal("An error occured cant find params: " + req.responseText);
	child = pom.xml.get_child_by_type(child, "param");
	if (!child)
		return fatal("An error occured can't find param: " + req.responseText);
	child = pom.xml.get_child_by_type(child, "value");
	if (!child)
		return fatal("An error occured cant find value: " + req.responseText);
	if (!child.childNodes.length)
		return fatal("No child nodes found: " + req.responseText);
	return pom.xml.make_element(child.childNodes[0]);
};
pom.xml.make_element = function(node) {
	var type = node.nodeName;
	var ret;
	var x;
	var xml_kids;
	var xml_kid;
	var kid;
	if (type == "array" || type == "params") {
		if (type == "array") {
			ret = new pom.array();
			xml_kids = this.get_child_by_type(node, "data");
		}
		else if (type == "params") {
			ret = new pom.params();
			xml_kids = node;
		}
		if (!xml_kids)
			return fatal("Unable to find data for " + type);
		for (x = 0; x < xml_kids.childNodes.length; x++) {
			xml_kid = xml_kids.childNodes[x];
	
			if (!xml_kid.childNodes.length)
				return fatal("Child node not found for a kid");
			if (xml_kid.childNodes[0].nodeName == "value")//for params they have a value wrapper
				kid = this.make_element(xml_kid.childNodes[0].childNodes[0]);
			else
				kid = this.make_element(xml_kid.childNodes[0]);
			ret.add_child(kid);
		}
	}
	else if (type == "struct") {
		ret = new pom.struct();
		for (x = 0; x < node.childNodes.length; x++) {
			xml_kid = node.childNodes[x];
			var name = this.get_child_by_type_value(xml_kid, "name");
			var value = this.get_child_by_type(xml_kid, "value");
			if (!value.childNodes.length)
				return fatal("Unable to find a childNode for a struct's value element");
			kid = this.make_element(value.childNodes[0]);
			ret.add_child(name, kid);
		}
	}
	else {
		ret = pom.node.create_node(type);
		ret.set_value(this.get_node_value(node));
	}
	return ret;
}

pom.xml.get_node_value = function(node) {
	/// <summary>Returns the value of an XML Node</summary>
	/// <param name="node" type="XmlNode"></param>
	/// <returns type="String"></returns>

	if (node.childNodes && node.childNodes.length)
		return node.childNodes[0].nodeValue;
	else if (node.nodeValue)
		return node.nodeValue;
	else
		return "";

}
pom.xml.get_child_by_type = function(xml, type) {
	/// <summary>Returns the first childNode that is of type type (or name in xml talk)</summary>
	/// <param name="xml" type="XmlNode"></param>
	/// <param name="type" type="String"></param>
	/// <returns type="XmlNode"></returns>

	for (var x = 0; x < xml.childNodes.length; x++) {
		if (xml.childNodes[x].nodeName == type)
			return xml.childNodes[x];
	}
	return null;
}
pom.xml.get_child_by_type_value = function(xml, type) {
	/// <summary>Returns the first childNode that is of type type's value (or empty string otherwise)</summary>
	/// <param name="xml" type="XmlNode"></param>
	/// <param name="type" type="String"></param>
	/// <returns type="XmlNode"></returns>

	for (var x = 0; x < xml.childNodes.length; x++) {
		if (xml.childNodes[x].nodeName == type)
			return this.get_node_value(xml.childNodes[x]);
	}
	return "";
}
pom.xml.get_children_by_type = function(xml, type) {
	/// <summary>Returns an Array of childNodes that is of type type (or name in xml talk)</summary>
	/// <param name="xml" type="XmlNode"></param>
	/// <param name="type" type="Array"></param>
	/// <returns type="XmlNode"></returns>
	var ret = [];
	for (var x = 0; x < xml.childNodes.length; x++) {
		if (xml.childNodes[x].nodeName == type)
			ret.push(xml.childNodes[x]);
	}
	return ret;
}
