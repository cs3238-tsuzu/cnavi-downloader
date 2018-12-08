(function(){
    const metaPlayListBaseURL = "https://hls-vod-auth.stream.co.jp/hls-vod-auth/waseda-wse/meta.m3u8?tk=";
    const downloaderBaseURL = "https://cnavi-downloader.herokuapp.com/download.php?auth_token2=";
    const authToken2 = document.cookie.split(';').map(x=>/auth_token2=(.*)/.exec(x)).filter(x=>x!==null)[0][1];
    const urlRegexp = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/;

    fetch(downloaderBaseURL + authToken2)
        .then(function(res) {
            return res.blob();
        })
        .then(function(blob){
            var a = document.createElement("a");
            document.body.appendChild(a);
            a.style = "display: none";

            if(window.URL) {
                const url = URL.createObjectURL(blob);
                a.href = url;
                a.download = document.title + ".ts";
                a.click();    
            } else {
                throw "f**k";
            }
        }).catch(err=>console.error(err));
})();