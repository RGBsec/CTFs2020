let ax = [];
const generateInputs = (a,b=!1)=>{
    for (let c = 0; 5 > c; c++) {
        const c = document.createElement("input");
        c.min = 0,
        c.max = 1e3,
        c.disabled = b,
        c.type = "number",
        a.appendChild(c)
    }
}
;
generateInputs(guesses),
generateInputs(results, !0);
const b = document.querySelector("button");
b.onclick = async()=>{
    var c = Math.floor;
    let d = !0;
    const e = guesses.querySelectorAll("input");
    if (e.forEach((a,b)=>{
        "" === a.value.trim() && (alert(`You haven't guessed anything for #${b + 1}`),
        d = !1)
    }
    ),
    !!d) {
        b.style.display = "none";
        const d = [...e].map(a=>parseInt(a.value));
        results.style.display = "block",
        results.querySelectorAll("input").forEach(a=>{
            ax.push(setInterval(()=>{
                a.value = c(1001 * Math.random())
            }
            , 100))
        }
        );
        const a = await fetch("/guess",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)});
        if (200 !== a.status) {
            const b = await a.text();
            return results.style.display = "none",
            ax.map(b=>clearInterval(b)),
            h.innerText = `An error occurred: ${b}`
        } else {
            const {results: b, flag: d} = await a.json();
            b.forEach((b,a)=>{
                setTimeout(()=>{
                    clearInterval(ax[a]),
                    [...results.querySelectorAll("input")][a].value = c(b)
                }
                , 1e3 * a + 5e3)
            }
            ),
            setTimeout(()=>{
                h.innerText = d ? `You've won the lottery!\nThe flag is: ${d}` : `Better luck next time!`
            }
            , 1e3 * b.length + 5500)
        }
    }
}
;
