"""Render code-native diagram previews. Not a screen recording or real assessment."""
import io, json, math, re, sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import cairosvg
data=json.load(sys.stdin)
out=Path(data["output"])
out.parent.mkdir(parents=True, exist_ok=True)
def font(size, bold=False):
    candidates=[Path("C:/Windows/Fonts")/("segoeuib.ttf" if bold else "segoeui.ttf"),Path("/usr/share/fonts/truetype/dejavu")/("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")]
    for candidate in candidates:
        if candidate.exists(): return ImageFont.truetype(str(candidate),size)
    return ImageFont.load_default(size=size)
def wrap(draw,text,x,y,width,size=15,color="#b9ccc9"):
    line=""
    for word in text.split():
        trial=(line+" "+word).strip()
        if draw.textlength(trial,font=font(size))>width and line:
            draw.text((x,y),line,font=font(size),fill=color);y+=size+6;line=word
        else:line=trial
    if line:draw.text((x,y),line,font=font(size),fill=color)
    return y+size+6
if data.get("profile"):
    source=data["svg"]
    frames=[]
    for i in range(30):
        # Animate only existing vector geometry; typography and background stay still.
        offset=math.sin(i/29*math.pi)*11
        svg=source.replace('rotate(-48)',f'rotate({-48+offset:.2f})').replace('rotate(48)',f'rotate({48-offset:.2f})')
        png=cairosvg.svg2png(bytestring=svg.encode(),output_width=800,output_height=300)
        frames.append(Image.open(io.BytesIO(png)).convert("RGB"))
    frames[0].save(out,save_all=True,append_images=frames[1:],duration=80,optimize=True,disposal=1)
else:
    graph=data["svg"].replace('<svg ', '<svg xmlns="http://www.w3.org/2000/svg" ',1)
    # Same SVG geometry and model states as the website, composed for a readable README.
    graph=re.sub(r'<path class="ob-trace"[\\s\\S]*?</svg>', '</svg>', graph)
    frames=[]
    points=[(76,271),(274,194),(486,241),(676,120)]
    for stage in range(4):
        im=Image.new("RGB",(800,450),"#101b1e");d=ImageDraw.Draw(im)
        d.text((26,19),"AD//HAMMER",font=font(23,True),fill="#f5efe3")
        d.text((467,25),"FICTIONAL DEMO / NOT LIVE OUTPUT",font=font(12),fill="#b9ccc9")
        for index,label in enumerate(["DISCOVER","MAP","INSPECT","REPORT"]):
            x=24+index*194
            d.rectangle((x,65,x+185,104),fill="#f5efe3" if index==stage else "#172629")
            d.text((x+12,76),f"0{index+1}  {label}",font=font(13,True),fill="#182421" if index==stage else "#b9ccc9")
        state=data["states"][stage];view=data["views"][stage]
        if stage<3:
            local=graph
            local=local.replace('class="ob-context"','class="ob-context" opacity=".32"')
            local=local.replace('class="ob-edges"', 'class="ob-edges" stroke="'+("#82e4b2" if state["evidence"] else "#f8795b")+'" opacity="'+(".22" if stage==0 else ".85")+'"')
            local=local.replace('class="ob-trace"','class="ob-trace" opacity="0"')
            diagram=Image.open(io.BytesIO(cairosvg.svg2png(bytestring=local.encode(),output_width=464,output_height=276))).convert("RGBA")
            im.paste(diagram,(15,115),diagram)
            d=ImageDraw.Draw(im)
            for index,(px,py) in enumerate(points):
                x=15+px/760*464;y=115+py/430*276
                selected=index==state["selected"]
                d.ellipse((x-13,y-13,x+13,y+13),fill="#f8795b" if selected else "#172629",outline="#f8795b" if selected else "#b9ccc9",width=1)
                d.text((x,y),str(index+1),font=font(12),fill="#182421" if selected else "#f5efe3",anchor="mm")
                name=data["nodes"][index]["name"]
                d.text((x,y+24),name,font=font(12),fill="#f5efe3",anchor="mt")
            d.line((497,125,497,391),fill="#40514f",width=1)
            node=data["nodes"][state["selected"]]
            d.text((522,137),node["kind"].upper(),font=font(12),fill="#d5b498")
            d.text((522,168),node["name"],font=font(25,True),fill="#f5efe3")
            short=["Objects are context, not proof.","A relationship is a hypothesis.","A fixture is attached explicitly."][stage]
            wrap(d,short,522,217,245,17)
            d.rectangle((522,288,769,343),fill="#82e4b2" if state["evidence"] else "#263637")
            wrap(d,view["label"],535,301,217,14,"#182421" if state["evidence"] else "#f5efe3")
            wrap(d,"Synthetic fixture only." if state["evidence"] else "No evidence attached.",522,361,244,13)
        else:
            d.rectangle((25,127,774,390),fill="#fffaf0")
            d.text((47,145),"ILLUSTRATIVE RECORD / 001",font=font(12),fill="#647064")
            d.text((47,172),"delegation",font=font(30,True),fill="#182421")
            d.text((47,223),"Evidence attached / fictional",font=font(17),fill="#913d26")
            d.line((47,262,749,262),fill="#d3cdbc")
            d.text((47,283),"ROUTE",font=font(12,True),fill="#647064")
            d.text((158,281),"svc-build → workstation-07 → delegation → tier-0",font=font(16),fill="#182421")
            d.text((47,321),"EVIDENCE",font=font(12,True),fill="#647064")
            wrap(d,"Synthetic fixture DEMO-001. Not a validation receipt.",158,319,570,16,"#182421")
        d.line((25,412,774,412),fill="#40514f")
        d.text((26,425),"OBSERVATION ≠ PROOF",font=font(12,True),fill="#f8795b")
        d.text((485,425),"Explore the interactive site ↗",font=font(13),fill="#f5efe3")
        frames.append(im)
    # Soft transitions between consistent states; finite 4.8-second total.
    animated=[frames[0]]
    durations=[600]
    for previous,current,hold in zip(frames,frames[1:],[800,900,1600]):
        for step in range(1,7):
            animated.append(Image.blend(previous,current,step/6))
            durations.append(50)
        animated.append(current)
        durations.append(hold)
    animated[0].save(out,save_all=True,append_images=animated[1:],duration=durations,optimize=True,disposal=1)
    frames[0].save(out.with_suffix(".png"),optimize=True)
print(json.dumps({"path":str(out),"bytes":out.stat().st_size}))
