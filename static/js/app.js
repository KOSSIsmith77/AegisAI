async function scan() {

    const url = document.getElementById("url").value;

    const response = await fetch("/scan", {

        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({
            url: url
        })

    });

    const data = await response.json();

    document.getElementById("result").textContent =
        JSON.stringify(data, null, 4);

}
