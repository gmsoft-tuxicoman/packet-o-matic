/// <reference path="minilib.js">
var pom = new Object();
pom.node = function() { };
Class.register_class("pom.node", pom.node);
pom.node._nodes = new Object();
pom.node.cast = function(node) {
	/// <summary>Casts a pom.node to a pom.node</summary>
	/// <param name="node" type="pom.node"></param>
	/// <returns type="pom.node"></returns>
	return node;
}
pom.node.register_node = function(type,node)
{
	/// <summary>Registers a new node type</summary>
	/// <param name="type" type="String"></param>
	/// <param name="node" type="pom.node">actual pom.node class that represents it</param>
	this._nodes[type] = node;
};
pom.node.create_node = function(type) {
	/// <summary>Creates a new pom.node of type type</summary>
	/// <param name="type" type="String"></param>
	/// <returns type="pom.node"></returns>
	if (!this._nodes[type]) {
		alert("Tried to create a pom.node of: " + type + " that i dont know of");
		return null;
	}
	return new this._nodes[type]();
}
pom.node.prototype._set_type = function(type) {
	/// <summary>Sets the type the node is</summary>
	/// <param name="type" type="String"></param>
	this._type = type;
};
pom.node.prototype.get_type = function() {
	/// <summary>Returns the type of node</summary>
	/// <returns type="String"></returns>
	return this._type;
};
pom.node.prototype.to_xml = function() {
	/// <summary>Returns a string containing the XML for the node</summary>
	/// <returns type="String"</returns>
	return "<" + this.get_type() + ">" + this.get_value() + "</" + this.get_type() + ">";
};
pom.node.prototype.is_stork = function() {
	/// <summary>Returns true if we are a stork</summary>
	/// <returns type="boolean"></returns>
	return false;
};
pom.node.prototype.set_value = function(value) {
	/// <summary>Sets our value to whatever</summary>
	/// <param name="value" type="Mixed"></param>
	this._value = value;
};
pom.node.prototype.get_value = function() {
	/// <summary>Sets our value to whatever</summary>
	/// <returns type="Mixed"></returns>
	return this._value;
};
pom.base64 = function() {
	Class.initialize_base(pom.base64, this);
	this._set_type("base64");
};
Class.register_class("pom.base64", pom.base64, pom.node);
pom.node.register_node("base64", pom.base64);
pom.boolean = function() {
	Class.initialize_base(pom.boolean, this);
	this._set_type("boolean");
};
pom.boolean.prototype.get_value = function() {
	if (this._value == "true" || this._value == "1")
		return 1;
	else
		return 0;
};
Class.register_class("pom.boolean", pom.boolean, pom.node);
pom.node.register_node("boolean", pom.boolean);
pom.double = function() {
	Class.initialize_base(pom.double, this);
	this._set_type("double");
};
pom.double.prototype.get_value = function() {
	return parseFloat(this._value);
};
Class.register_class("pom.double", pom.double, pom.node);
pom.node.register_node("double", pom.double);

pom.integer = function() {
	Class.initialize_base(pom.integer, this);
	this._set_type("i4");
};
pom.integer.prototype.get_value = function() {
	return parseInt(this._value);
};
Class.register_class("pom.integer", pom.integer, pom.node);
pom.node.register_node("integer", pom.integer);
pom.node.register_node("i4", pom.integer);
pom.node.register_node("int", pom.integer);
pom.string = function() {
	Class.initialize_base(pom.string, this);
	this._set_type("string");
};
Class.register_class("pom.string", pom.string, pom.node);
pom.node.register_node("string", pom.string);
pom.stork_node = function(){
	Class.initialize_base(pom.stork_node,this);
}
Class.register_class("pom.stork_node",pom.stork_node,pom.node);
pom.stork_node._storks = {};
pom.stork_node.register_stork = function(type, stork) {
	/// <summary>Registers a new stork type</summary>
	/// <param name="type" type="String"></param>
	/// <param name="stork" type="pom.stork_node">actual pom.stork_node class that represents it</param>
	this._storks[type] = stork;
}
pom.stork_node.cast = function(stork_node) {
	/// <summary>Takes a stork node and returns it with proper type</summary>
	/// <param name="stork_node" type="pom.stork_node"></param>
	/// <returns type="pom.stork_node"></returns>
	return stork_node;
}
pom.stork_node.prototype.set_value = function() {
	alert("CANNOT SET VALUES ON STORK NODES");
};
pom.stork_node.prototype.is_stork = function() {
	return true;
};

pom.array = function() {
	Class.initialize_base(pom.array, this);
	this._children = [];
	this._set_type("array");
};
Class.register_class("pom.array",pom.array,pom.stork_node);
pom.array.prototype._children = [];
pom.array.cast = function(array) {
	/// <summary>Casts a pom array to an pom array</summary>
	/// <param name="array" type="pom.array"></param>
	/// <returns type="pom.array"></returns>
	return array;
}
pom.array.prototype.add_child = function(node) {
	/// <summary>Adds a child to the stork_node</summary>
	/// <param name="node" type="pom.node"></param>
	this._children.push(node);
};
pom.array.prototype.get_children = function() {
	/// <summary>Returns the children in an array</summary>
	/// <returns type="Array" elementType="pom.node"></returns>
	return this._children;
};
pom.array.prototype.to_xml = function() {
	var ret = "<array><data>";
	var kids = this.get_children();
	for (var x = 0; x < kids.length; x++) {
		ret += "<value>" + kids[x].to_xml() + "</value>\n";
	}
	ret += "</data></array>";
	return ret;
};
pom.params = function() {
	Class.initialize_base(pom.params, this);
	this._set_type("params");
};
Class.register_class("pom.params", pom.params, pom.array);
pom.params.cast = function(params) {
	/// <summary>Casts a pom params to an pom params</summary>
	/// <param name="params" type="pom.params"></param>
	/// <returns type="pom.params"></returns>
	return params;
}
pom.params.prototype.to_xml = function() {
	var ret = "<params>";
	var kids = this.get_children();
	for (var x = 0; x < kids.length; x++) {
		ret += "<param><value>" + kids[x].to_xml() + "</value></param>\n";
	}
	ret += "</params>";
	return ret;
};
pom.struct = function(){
	Class.initialize_base(pom.struct,this);
	this._set_type("struct");
	this._children = {};
}
Class.register_class("pom.struct",pom.struct,pom.stork_node);
pom.struct.prototype._children = {};
pom.struct.cast = function(struct) {
	/// <summary>Casts a pom struct to an pom struct</summary>
	/// <param name="struct" type="pom.struct"></param>
	/// <returns type="pom.struct"></returns>
	return struct;
}
pom.struct.prototype.add_child = function(name, value) {
	/// <summary>Adds a child to the struct</summary>
	/// <param name="name" type="String"></param>
	/// <param name="value" type="pom.node"></param>
	this._children[name] = value;
};
pom.struct.prototype.get_children = function() {
	/// <summary>Returns a hash of name/value pairs with values being pom.nodes</summary>
	/// <returns type="Hash"></returns>
	return this._children;
}
pom.struct.prototype.get_child = function(name) {
	/// <summary>Returns a pom.node child of the given name</summary>
	/// <param name="name" type="String"></param>
	/// <returns type="pom.node"></returns>
	return this._children[name];
}
pom.struct.prototype.to_xml = function() {
	var ret = "<struct>";
	for (var child in this._children) 
		ret += "<member><name>" + child + "</name><value>" + child.to_xml() + "</value></member>";
	
	ret += "</struct>";
	return ret;
}