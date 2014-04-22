//
document.addEventListener('DOMContentLoaded', function ()
{
	// add the click event listener
	document.getElementById('click-me').addEventListener('click', gobuttonpressed);

	// add the field change listeners
	document.getElementById('siteselect').addEventListener('input', inputchanged, false);
	document.getElementById('masterpass').addEventListener('input', inputchanged, false);

	// auto fill the site select box to the current url
	var siteSelectBox = document.querySelector(".siteselect");
	chrome.tabs.query({ currentWindow: true, active: true }, function (tabs)
	{
		var tabURI = tabs[0].url;
		var domain = tabURI.match(/^[\w-]+:\/*\[?([\w\.:-]+)\]?(?::\d+)?/)[1];
		siteSelectBox.value = domain;
	});
});

function inputchanged(e)
{
	var encoded = passy(document.getElementById('siteselect').value, document.getElementById('masterpass').value)[0]
	document.getElementById('outputbox').value = encoded;
	chrome.tabs.executeScript({
		code: 'document.activeElement.value ="' + document.getElementById('outputbox').value + '";'
	});
};

function gobuttonpressed(e)
{
	
};

