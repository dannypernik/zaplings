function adjust(color, amount) {
  return '#' + color.replace(/^#/, '').replace(/../g, color =>
    ('0' + Math.min(255, Math.max(0, parseInt(color, 16) + amount)).toString(16)).substr(-2));
};

let root = document.documentElement;

root.style.setProperty('--primary-color', primaryColor );
root.style.setProperty('--secondary-color', secondaryColor );

function getContrastYIQ(hexcolor){
  var r = parseInt(hexcolor.substring(1,3),16);
  var g = parseInt(hexcolor.substring(3,5),16);
  var b = parseInt(hexcolor.substring(5,7),16);
  var yiq = ((r*299)+(g*587)+(b*114))/1000;
  return (yiq >= 128) ? 'saturate(0.7)' : 'brightness(1.2)';
}

var hoverFilter = getContrastYIQ(secondaryColor)
root.style.setProperty('--hover-filter', hoverFilter );
