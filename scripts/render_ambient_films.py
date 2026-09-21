"""Render seamless functional-diagram loops. All objects and flows are illustrative."""
import math
import shutil
import subprocess
from PIL import Image, ImageDraw
from render_cli_film import OUT, font

W, H, FPS, DURATION = 960, 300, 24, 8
BG, INK, MUTED = '#0c1419', '#f0eee7', '#9db2ba'
COLORS = ['#8bd9bb', '#f2bb69', '#ff9d87']

def render(kind, t):
    im = Image.new('RGB', (W,H), BG)
    d = ImageDraw.Draw(im)
    d.text((30,20), 'AD//HAMMER  /  '+('RELATIONSHIPS' if kind=='evidence' else 'REPORT HANDOFF'), font=font(16,mono=True),fill=MUTED)
    d.text((708,20),'ILLUSTRATIVE FLOW',font=font(15,mono=True),fill=MUTED)
    labels = ['DIRECTORY', 'GRAPH', 'REVIEW'] if kind=='evidence' else ['JSON', 'HTML', 'MARKDOWN']
    center = (480,145)
    endpoints = [(180,145),(480,145),(780,145)] if kind=='evidence' else [(720,87),(720,158),(720,229)]
    starts = [(180,145),(480,145)] if kind=='evidence' else [(240,158)]*3
    ends = endpoints[1:] if kind=='evidence' else endpoints
    for i,(start,end) in enumerate(zip(starts,ends)):
        d.line((*start,*end),fill='#354a53',width=2)
        for particle in range(4):
            p = (t/DURATION + particle/4) % 1
            x,y = start[0]+(end[0]-start[0])*p,start[1]+(end[1]-start[1])*p
            d.ellipse((x-4,y-4,x+4,y+4),fill=COLORS[i])
    if kind=='evidence':
        for i,(x,y) in enumerate(endpoints):
            radius = 36 + 3*math.sin(t/DURATION*2*math.pi+i*2*math.pi/3)
            d.ellipse((x-radius,y-radius,x+radius,y+radius),outline=COLORS[i],width=2)
            d.ellipse((x-23,y-23,x+23,y+23),fill='#16262e')
            d.text((x,y),str(i+1).zfill(2),font=font(19,mono=True),anchor='mm',fill=INK)
            d.text((x,219),labels[i],font=font(20,mono=True),anchor='mm',fill=COLORS[i])
    else:
        d.rounded_rectangle((125,112,355,204),radius=9,fill='#16262e',outline=COLORS[0],width=2)
        d.text((240,158),'ONE RECORD',font=font(23,True),anchor='mm',fill=INK)
        for i,(x,y) in enumerate(endpoints):
            d.rounded_rectangle((x-100,y-24,x+100,y+24),radius=6,fill='#16262e',outline=COLORS[i])
            d.text((x,y),labels[i],font=font(18,mono=True),anchor='mm',fill=COLORS[i])
    d.text((30,268),'Context travels with the finding. Motion is not evidence of a live assessment.',font=font(16),fill=MUTED)
    return im

for kind in ['evidence','report']:
    name = kind+'-loop'
    cmd = [shutil.which('ffmpeg'),'-y','-v','error','-f','rawvideo','-pixel_format','rgb24','-video_size',f'{W}x{H}','-framerate',str(FPS),'-i','-','-an','-c:v','libx264','-crf','22','-pix_fmt','yuv420p','-movflags','+faststart',str(OUT/(name+'.mp4'))]
    process = subprocess.Popen(cmd,stdin=subprocess.PIPE)
    try:
        for frame in range(FPS*DURATION):
            im = render(kind,frame/FPS)
            if frame == 0: im.save(OUT/(name+'.jpg'),quality=92)
            process.stdin.write(im.tobytes())
        process.stdin.close()
        assert process.wait()==0, 'Encoder failed'
    finally:
        if process.poll() is None: process.kill(); process.wait()
    print(name+' rendered')
