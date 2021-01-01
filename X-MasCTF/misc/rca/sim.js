var noSquares = 70;
var noSquaresY = 70;
var matrix = [];
var start = 160760000; // Legend has it that he who saw the Big Bang holds all the secrets of this Universe

function unpack(h) {
	var bits = [], parsed;
	for (var i = 0, len = h.length; i < len; i += 2) {
		parsed = parseInt(h.substring(i, i + 2), 16).toString(2);
		for(var j = parsed.length; j < 8; ++j)
			parsed = "0" + parsed;

		for(var j = 0, len2 = parsed.length; j < len2; ++j) {
			if(parsed[j] == '1') {
				bits.push(1);
			}
			else {
				bits.push(0);
			}
		}
	}
	return bits;
}


function getCell(x, y) {
	if(x < 0) x = noSquares - 1;
	if(x >= noSquares) x = 0;
	if(y < 0) y = noSquares - 1;
	if(y >= noSquares) y = 0;
	return matrix[y][x];
}


function putCell(x, y, value) {
	if(x < 0) x = noSquares - 1;
	if(x >= noSquares) x = 0;
	if(y < 0) y = noSquares - 1;
	if(y >= noSquares) y = 0;
	matrix[y][x] = value;
}


function getSquare(x, y) {
	return [getCell(x, y), getCell(x + 1, y), getCell(x, y + 1), getCell(x + 1, y + 1)];
}


function putSquare(x, y, vals) {
	putCell(x, y, vals[0]);
	putCell(x + 1, y, vals[1]);
	putCell(x, y + 1, vals[2]);
	putCell(x + 1, y + 1, vals[3]);
}


function processSquare(x, y) {
	var square = getSquare(x, y);
	var noLiveCells = square.reduce((a, b) => a + b);
	if(noLiveCells != 2) {
		for(var i = 0;i < square.length; ++i) {
			if(square[i] == 1) {
				square[i] = 0;
			} else {
				square[i] = 1;
			}
		}
	}
	if(noLiveCells == 3) {
		var newSquare = [0, 0, 0, 0];
		newSquare[0] = square[3];
		newSquare[1] = square[2];
		newSquare[2] = square[1];
		newSquare[3] = square[0];
		square = newSquare;
	}
	return square;
}


function nextMatrix(m, roundNo) {
	var startCoord = -(roundNo % 2);

	console.log('Round #' + roundNo.toString());
	for(var i = startCoord;i < noSquares; i += 2) {
		for(var j = startCoord;j < noSquares; j += 2) {
			putSquare(i, j, processSquare(i, j));
		}
	}
	return m;
}


function setupMatrix() {
	const initialState_packed = "44f694c51bd68cd06d977e67ab21311db80481a9da4a2dc022bbf1373532586444999029d7a516e183a2ab80bb3432382d4c713538e53ce1950b85c0b038d129ac9a503dca2fc015e3086aa1c129e911bb88a6a1116b41535761800c5a0c14ab9f7e18b0c511c456d6ae7950189bd9086a3c13820350750c8d7c7a6f98a00c3665840517c4a49c992604d4abccb3ea05008681b126fe6b802c012251ddf68b19c295d4838868c7215c092dd55c084870e4461210045427cd8f0a71108840801f42dab83480111899caf7b81ac8c0c000217d69043a0670000dc05b409d84a4881a056a2c562c15880b3008edc306d8044881b84192157b57704820003a2b3d4068a544022970cb628526850500cc4cd1600d04003082a642fad829c4198b13f3d5206918125004502c985160001002014018fc68301a0213c40a4ac7fbe04670025a02a868061124180eb044ed622604e00810dc07efd8c002044308384dc02824e9162801e84aa0111880940996f307ae62360060ba64ede92b642920010228098a4ce910944182a04ffe670970120921d1a0b7200c3194502ca26330d9c041300484df3b525ac906221a2e1ebdf10248808eed6033699e2142040db94a9695a024929a20218f512455008da200e85c86452a704a90f639c03d88820408242d34a2d4ad0558829a83d3a2881dc7224d2e62801bc1452028728da094c353276753b06e681fa8120e89842217dfef660254b1d1fb8c2fd0953ea02de6fad34e64a234634401c6bb2a986ca05df4047c34bbb84d7878ae566181134b6db583ceec955a191e36a2f156f248ab39d620d70c90086aa9b738907e93b9e191b01dc7855c680ca090";
	const initialState = unpack(initialState_packed);
	for(var i = 0; i < noSquares; ++i) {
		matrix[i] = [];
		for(var j = 0;j < noSquares; ++j) {
			matrix[i][j] = initialState[i * noSquares + j];
		}
	}
	var now = Math.floor(Date.now() / 1000 / 10);
	var savedStateTime = 160760160;
	for(var i = savedStateTime + 1; i <= now; i += 1) {
		matrix = nextMatrix(matrix, i - start);
	}
	var nnow = Math.floor(Date.now() / 1000 / 10);
	while(nnow != now) {
		for(var i = now+ 1; i <= nnow; i += 1) {
			matrix = nextMatrix(matrix, i - start);
		}
		now = nnow;
		nnow = Math.floor(Date.now() / 1000 / 10);
	}
}


function drawCell(c, ctx, x, y) {
	var w_factor = Math.ceil(c.width / noSquares);
	var h_factor = w_factor;
	ctx.fillRect(x * w_factor, y * h_factor, w_factor, h_factor);
}


function drawScene(c) {
	var ctx = c.getContext('2d');
	ctx.clearRect(0, 0, c.width, c.height);
	for(var i = 0; i < noSquares; ++i) {
		for(var j = 0;j < noSquaresY; ++j) {
			if(matrix[i][j] == 1) {
				drawCell(c, ctx, i, j);
			}
		}
	}
}


function refreshCanvas() {
	var b = document.getElementsByTagName('body')[0];
	var c = document.getElementById('bkgrnd');
	var w = b.scrollWidth;
	var h = b.scrollHeight;
	c.width = w;
	c.height = h;
	noSquaresY = Math.ceil(h / w * 100);
	var ctx = c.getContext('2d');
	ctx.fillStyle = "lime";
	drawScene(c);
}


function nextFrame() {
	var c = document.getElementById('bkgrnd');
	var now = Math.floor(Date.now() / 1000 / 10);
	var roundNo = now - start;
	matrix = nextMatrix(matrix, roundNo);
	drawScene(c);
}


function addThingy() {
	var b = document.getElementsByTagName('body')[0];
	var f = document.getElementById('front');
	var d = document.createElement('div');
	d.classList.add('background');
	d.innerHTML = '<canvas id="bkgrnd"></canvas>';
	b.insertBefore(d, f);
}


function initialize() {
	addThingy();
	setupMatrix();
	window.onresize = refreshCanvas;
	refreshCanvas();
	setInterval(nextFrame, 10 * 1000);
}


initialize();
