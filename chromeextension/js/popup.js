//
document.addEventListener('DOMContentLoaded', function ()
{
	// add the click event listener
	document.getElementById('first-button').addEventListener('click', firstbuttonpressed);
	document.getElementById('all-button').addEventListener('click', allbuttonpressed);
	document.getElementById('clip-button').addEventListener('click', copybuttonpressed);

	// add the field change listeners
	document.getElementById('siteselect').addEventListener('input', inputchanged, false);
	document.getElementById('masterpass').addEventListener('input', inputchanged, false);

	// auto fill the site select box to the current url
	var siteSelectBox = document.querySelector(".siteselect");

	if (chrome.tabs)
	{
		chrome.tabs.query({ currentWindow: true, active: true }, function (tabs)
		{
			var tabURI = tabs[0].url;
			var domain = tabURI.match(/^[\w-]+:\/*\[?([\w\.:-]+)\]?(?::\d+)?/)[1];
			siteSelectBox.value = domain;
		});
	}
});

function inputchanged(e)
{
	var encoded = passy(document.getElementById('siteselect').value, document.getElementById('masterpass').value)[0]
	document.getElementById('outputbox').value = encoded;
	fillActivePasswordField();
};

function fillActivePasswordField()
{
	if (chrome.tabs)
	{
		chrome.tabs.executeScript({
			code: 'if(document.activeElement && document.activeElement.type.toLowerCase() === "password") { document.activeElement.value = "' + document.getElementById('outputbox').value + '"; }'
			//code: 'document.activeElement.value ="' + document.getElementById('outputbox').value + '";'
		});
	}
};

function fillFirstPasswordField()
{
	if (chrome.tabs)
	{
		chrome.tabs.executeScript({
			code: 'var ary = []; var inputs = document.getElementsByTagName("input"); for (var i=0; i<inputs.length; i++) { if (inputs[i].type.toLowerCase() === "password") { ary.push(inputs[i]); } }; if(ary.length > 0) { ary[0].value = "' + document.getElementById('outputbox').value + '"; }'
			//code: 'document.activeElement.value ="' + document.getElementById('outputbox').value + '";'
		});
	}
};

function fillAllPasswordFields()
{
	if (chrome.tabs)
	{
		chrome.tabs.executeScript({
			code: 'var ary = []; var inputs = document.getElementsByTagName("input"); for (var i=0; i<inputs.length; i++) { if (inputs[i].type.toLowerCase() === "password") { ary.push(inputs[i]); } }; for(var i = 0; i<ary.length; ++i) { ary[i].value = "' + document.getElementById('outputbox').value + '"; }'
			//code: 'document.activeElement.value ="' + document.getElementById('outputbox').value + '";'
		});
	}
};

function firstbuttonpressed(e)
{
	fillFirstPasswordField();
};

function allbuttonpressed(e)
{
	fillAllPasswordFields();
};

function copybuttonpressed(e)
{
	document.getElementById("outputbox").select();
	console.log(document.getElementById("outputbox").value);
	document.execCommand("copy", false, null);
};

