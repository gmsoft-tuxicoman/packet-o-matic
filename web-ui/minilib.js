Array.append = function(arr, arr2) {
	/// <summary>Appends the items from the second array onto the first</summary>
	/// <param name="arr" type="Array">Array to append to</param>
	/// <param name="arr2" type="Array">Array of items to append</param>
	/// <returns type="Array">arr with arr2's items at the end</returns>

	for (var x = 0; x < arr2.length; x++)
		arr[arr.length] = arr2[x];
	return arr;
};
Array.concat = function() {
	/// <summary>Concats all the arguements together into one new array, if an arguement is an array appends each item in that array</summary>
	/// <returns type="Array"></returns>

	var array = [];
	for (var i = 0, length = arguments.length; i < length; i++) {
		if (typeof arguments[i].length != "undefined") {
			for (var j = 0, arrayLength = arguments[i].length; j < arrayLength; j++)
				array.push(arguments[i][j]);
		} else {
			array.push(arguments[i]);
		}
	}
	return array;

};

Function.prototype.bind = function() {
	/// <summary>Ties the proper 'this' to the function, and allows argument binding, first argument should be this rest can be arguments to bind</summary>
	/// <returns type="Function">a function pointer to the new function</returns>

	if (arguments.length < 2 && (typeof arguments[0] == "undefined")) return this;
	var __method = this, args = $A(arguments), object = args.shift();
	return function() {
		return __method.apply(object, Array.concat(args, arguments));
	};
};
Object.extend = function(destination, source) {
	/// <summary>Takes two classes and copies all members/methods to the first from the second(inheritence)</summary>
	/// <param name="destination" type="Class">Child class to be extended</param>
	/// <param name="source" type="Class">The class we want to extend/inherit from</param>
	for (var property in source) {
		if (property != "prototype")
			destination[property] = source[property];
	}
};
if (!window.Class)
	window.Class = new Object();
Class.get_name = function(class_obj) {
	/// <summary>Returns the name of the static class passed in(as long as its registered)</summary>
	/// <param name="class_obj" type="Class">The static class to get the name of</param>
	/// <returns type="String"></returns>
	return class_obj.__typeName;
};
Class.register_class = function(name, class_obj, base_class) {
	/// <summary>Registers a new class and establishes inheritence</summary>
	/// <param name="name" type="String">The full class name including namespace(ie Zoo.panes.pane)</param>
	/// <param name="class_obj" type="Class">The static class itself (should be same as name but without quotes so the actual object)</param>
	/// <param name="base_class" type="Class">The base static class itself if the object is inheriting from another class</param>
	if (!window.__classes)
		window.__classes = {};
	if (window.__classes[name.toUpperCase()]) {
		alert("Unable to register class: " + name + " as a class already exists with that name");
		return;
	}
	window.__classes[name.toUpperCase()] = class_obj;
	class_obj.prototype.constructor = class_obj;
	class_obj.__class = true;
	class_obj.__typeName = name;
	if (document.readyState && document.readyState.length == 0)
		class_obj.resolveInheritance = Class.resolve_inheritance.bind(Class, class_obj);
	if (base_class) {
		class_obj.__baseType = base_class;
		class_obj.__basePrototypePending = true;
	}
	if (!window.__registeredTypes)
		window.__registeredTypes = {};
	window.__registeredTypes[name] = true;

};
Class.resolve_inheritance = function(class_obj) {
	/// <summary>Copies any inherited methods over to the class inheriting them</summary>
	/// <param name="class_obj" type="Class">The static class to resolve inheritance on </param>

	//This class is called the first time the constructor is initailized and not during register_class so that if a base class function is prototyped AFTER an inheriting class is registered it still will get copied over
	if (class_obj.__basePrototypePending) {
		var baseType = class_obj.__baseType;
		Class.resolve_inheritance(baseType);
		for (var memberName in baseType.prototype) {
			if (!class_obj.prototype[memberName])
				class_obj.prototype[memberName] = baseType.prototype[memberName];
		}
		delete class_obj.__basePrototypePending;
	}
};
Class.initialize_base = function(class_obj, instance, base_arguments) {
	/// <summary>Initializes any base classes and automatically resolves inheritence</summary>
	/// <param name="class_obj" type="Class">The static class of the instance</param>
	/// <param name="instance" type="Instance">The instance of the class (normally this)</param>
	/// <param name="base_arguments" type="Array">Optional array of arguments to pass to base class constructor</param>
	Class.resolve_inheritance(class_obj);
	if (class_obj.__baseType) {
		if (!base_arguments)
			class_obj.__baseType.apply(instance);
		else
			class_obj.__baseType.apply(instance, base_arguments);
	}
};

function $(id) {
	/// <param name="id" type="String"></param>
	/// <returns type="HTMLEelement" domElement="true" mayBeNull="true"></returns>
	if (typeof (id) == "object" || typeof (id) == "function") // OBJECT tags seem to return typeof function
		return id;
	return document.getElementById(id);
}
function $A(iterable) {
	/// <summary>Takes any iteratable item (has a length and responds to indexing) and returns a true array</summary>
	/// <param name="iterable" type="IterableObject"></param>
	/// <returns type="Array"></returns>

	if (!iterable) return [];
	if (iterable.toArray) return iterable.toArray();
	var length = iterable.length || 0, results = new Array(length);
	while (length--) results[length] = iterable[length];
	return results;
}
function $F(name) {
	/// <summary>Returns the value of the form element passed</summary>
	/// <param name="" type=""></param>
	/// <returns type=""></returns>

	var result = $(name);
	if (result && result.type.toLowerCase() == "radio")
		result = false;
	if (!result) {
		result = document.getElementsByName(name);
		if (result.length > 1) {
			for (var i = 0; i < result.length; i++)
				if (result[i].checked)
				return result[i].value;
		}
		else
			result = result[0];
	}
	if (result.type && (result.type.toLowerCase() == "checkbox"))
		return result.checked;
	else
		return result.value;
}
function $$(arg) {
	return document.getElementsByTagName(arg);
}


if (!window.Element)
	Element = new Object();


Element.visible = function(element) {
	return $(element).style.display != 'none';
};

Element.toggle = function(element) {
	element = $(element);
	Element[Element.visible(element) ? 'hide' : 'show'](element);
	return element;
};
Element.hide = function(element) {
	$(element).style.display = 'none';
	return element;
};
Element.focus = function(element) {
	$(element).focus();
	return element;
};
Element.show = function(element) {
	$(element).style.display = '';
	return element;
};
Element.remove = function(element) {
	// OBJECT tags are not typeof object - they become typeof function - but they can still be removed
	element = $(element);
	if (element && element.parentNode)
		element.parentNode.removeChild(element);
	return element;
};
String.stripTags = function(string) {
	return string.replace(/<\/?[^>]+>/gi, '');
};
String.strip = function(string) {
	return string.replace(/^\s+/, '').replace(/\s+$/, '');
};
String.camelize = function(string) {
	var parts = string.split('-'), len = parts.length;
	if (len == 1) return parts[0];

	var camelized = string.charAt(0) == '-'
      ? parts[0].charAt(0).toUpperCase() + parts[0].substring(1)
      : parts[0];

	for (var i = 1; i < len; i++)
		camelized += parts[i].charAt(0).toUpperCase() + parts[i].substring(1);

	return camelized;
};
Element.getStyle = function(element, style) {
	element = $(element);
	if ('float' == style || 'cssFloat' == style)
		style = (typeof element.style.styleFloat != 'undefined' ? 'styleFloat' : 'cssFloat');
	style = String.camelize(style);
	var value = element.style[style];
	if (!value) {
		if (document.defaultView && document.defaultView.getComputedStyle) {
			var css = document.defaultView.getComputedStyle(element, null);
			value = css ? css[style] : null;
		} else if (element.currentStyle) {
			value = element.currentStyle[style];
		}
	}

	if ((value == 'auto') && ['width', 'height'].include(style) && (element.getStyle('display') != 'none'))
		value = element['offset' + style.capitalize()] + 'px';

	if (window.opera && ['left', 'top', 'right', 'bottom'].include(style))
		if (Element.getStyle(element, 'position') == 'static') value = 'auto';
	if (style == 'opacity') {
		if (value) return parseFloat(value);
		value = (element.getStyle('filter') || '').match(/alpha\(opacity=(.*)\)/);
		if (value && value[1])
			return parseFloat(value[1]) / 100;
		return 1.0;
	}
	return value == 'auto' ? null : value;
};

Element.getDimensions = function(element) {
	element = $(element);
	var display = Element.getStyle(element, 'display');
	if (display != 'none' && display != null) // Safari bug
		return { width: element.offsetWidth, height: element.offsetHeight };

	var els = element.style;
	var originalVisibility = els.visibility;
	var originalPosition = els.position;
	var originalDisplay = els.display;
	els.visibility = 'hidden';
	els.position = 'absolute';
	els.display = 'block';
	var originalWidth = element.clientWidth;
	var originalHeight = element.clientHeight;
	els.display = originalDisplay;
	els.position = originalPosition;
	els.visibility = originalVisibility;
	return { width: originalWidth, height: originalHeight };
};
Element.getHeight = function(element) {
	return Element.getDimensions(element).height;
};
Element.getWidth = function(element) {
	return Element.getDimensions(element).width;
};
function $T(text) {
	return document.createTextNode(text);
}
function $E(name) {
	return document.createElement(name);
}
function _network_failure(req) {
	alert("Unable to complete network request: " + req.statusText + "-" + req.status);
}
function _network_state_change(transport, on_done) {
	if (transport.readyState == 4) {
		if (transport.status == 0 || (transport.status >= 200 && transport.status < 300))
			on_done(transport);
		else
			_network_failure(transport);
	}

}
function get_xml_http_request() {
	try { return new XMLHttpRequest(); } catch (ex) { }
	try { return new ActiveXObject('Msxml2.XMLHTTP'); } catch (ex) { }
	try { return new ActiveXObject('Microsoft.XMLHTTP'); } catch (ex) { }
	return "";
}
function network_request(method, url, parameters, on_done) {
	var transport = get_xml_http_request();
	if (!transport)
		return;
	transport.onreadystatechange = _network_state_change.bind(this, transport, on_done);
	var url_str = url;
	var params_str = parameters;
	if (method.toUpperCase() == "GET") {
		if (parameters)
			url_str += "?" + parameters;
		params_str = "";
	}
	transport.open(method.toUpperCase(), url_str);
	if (method.toUpperCase() == "POST")
		transport.setRequestHeader('Content-Type', 'text/xml');
	transport.send(params_str);
	return transport;
}

