"""Generate an original functional-diagram film, not a live CLI recording.

Requires Pillow and ffmpeg on PATH. Writes only the three named preview assets.
Run from any directory: python scripts/render_cli_film.py
"""
import math
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'site' / 'assets'
W, H, FPS, SECONDS = 1280, 720, 24, 18
BG, PANEL, LINE = '#0c1419', '#142128', '#35454c'
WHITE, MUTED = '#f0eee7', '#acbcc3'
COLORS = ['#8bd9bb', '#f2bb69', '#ff9d87', '#bbadee']
STAGES = ['COLLECT', 'INSPECT', 'RETAIN CONTEXT', 'REVIEW']
TITLES = ['Read the directory.', 'Evaluate the template.', 'Keep the context.', 'Make a defensible decision.']
NOTES = [
    ['Approved LDAPS scope', 'Template data enters the checker', 'No certificate is requested'],
    ['Fictional template: Example-User', 'Rules evaluate configuration', 'A signal needs interpretation'],
    ['Rule + affected object', 'Explanation + remediation', 'JSON findings, not an all-clear'],
    ['Confirm permissions and CA settings', 'Account for patches and missing reads', 'Record the limits of the assessment'],
]

@lru_cache(maxsize=30)
def font(size, bold=False, mono=False):
    filename = 'consola.ttf' if mono else ('segoeuib.ttf' if bold else 'segoeui.ttf')
    path = Path('C:/Windows/Fonts') / filename
    if not path.exists():
        path = Path('/usr/share/fonts/truetype/dejavu') / ('DejaVuSansMono.ttf' if mono else 'DejaVuSans.ttf')
    return ImageFont.truetype(str(path), size)

def frame(t):
    im = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(im)
    stage = min(3, int(t / 4.5))
    local = (t - stage * 4.5) / 4.5
    accent = COLORS[stage]
    d.text((48, 30), 'AD//HAMMER', font=font(22, True, True), fill=WHITE)
    d.text((775, 36), 'MOTION STUDY  /  SYNTHETIC EXAMPLE', font=font(17, mono=True), fill=MUTED)
    d.line((48, 77, 1232, 77), fill=LINE, width=1)
    d.text((48, 105), f'0{stage+1} / AD CS TEMPLATE REVIEW', font=font(18, mono=True), fill=accent)
    d.text((48, 142), TITLES[stage], font=font(48, True), fill=WHITE)
    # Four stages on a shared path. Moving packets are illustrative, not traffic telemetry.
    xs, y = [156, 480, 804, 1128], 295
    for i in range(3):
        d.line((xs[i]+40, y, xs[i+1]-40, y), fill=LINE, width=2)
        for packet in range(3):
            p = ((t * .30) + packet / 3) % 1
            x = xs[i]+40 + (xs[i+1]-xs[i]-80)*p
            color = COLORS[i] if i <= stage else '#53676f'
            d.line((x-12,y,x,y),fill=color,width=3)
    for i, x in enumerate(xs):
        color = COLORS[i] if i <= stage else '#53676f'
        d.ellipse((x-39,y-39,x+39,y+39),fill=PANEL,outline=color,width=2)
        if i == stage:
            # A rotating progress arc makes the currently inspected stage explicit.
            d.arc((x-48,y-48,x+48,y+48),t*65,t*65+240,fill=color,width=3)
        d.text((x,y),f'0{i+1}',anchor='mm',font=font(23,True,True),fill=color)
        d.text((x,354),STAGES[i],anchor='mm',font=font(17,mono=True),fill=color)
    d.rounded_rectangle((48,401,750,621),radius=14,fill=PANEL,outline=LINE)
    d.text((72,420),'CHECK ADCS / CONCEPTUAL FLOW',font=font(15,mono=True),fill=accent)
    if stage == 0:
        # Data rows travel into a template collection, then settle.
        for j, label in enumerate(['Directory objects', 'Certificate templates', 'Configuration attributes']):
            offset = int(max(0, 1-local*3+j*.15)*34)
            yy = 464+j*43
            d.rounded_rectangle((72+offset,yy,716,yy+31),radius=5,fill='#20343b')
            d.text((88+offset,yy+4),label,font=font(17,mono=True),fill=WHITE)
    elif stage == 1:
        d.text((72,468),'Example-User',font=font(27,True),fill=WHITE)
        d.text((72,510),'Inspect configuration flags',font=font(21),fill=MUTED)
        d.rectangle((72,562,714,566),fill=LINE)
        d.rectangle((72,562,72+int(642*min(1,local*1.7)),566),fill=accent)
        scan_x = 80+int((local*1.5 % 1)*620)
        d.line((scan_x,454,scan_x,547),fill=accent,width=2)
    elif stage == 2:
        rows = [('id','rule identifier'),('affected','Example-User'),('detail','configuration context'),('remediation','review guidance')]
        for j,(key,value) in enumerate(rows):
            yy = 458+j*34
            d.text((72,yy),key,font=font(18,mono=True),fill=accent)
            n = int(max(0,min(1,local*4-j*.35))*len(value))
            d.text((266,yy),value[:n],font=font(18,mono=True),fill=WHITE)
    else:
        for j,label in enumerate(['Permissions + host context','CA settings + patch state','Evidence + scope limitations']):
            yy=463+j*44
            d.rectangle((75,yy+3,92,yy+20),outline=accent,width=2)
            d.text((112,yy),label,font=font(21),fill=WHITE)
        d.text((530,427),'MANUAL REVIEW',font=font(15,mono=True),fill=accent)
    d.text((792,422),'WHAT THIS MEANS',font=font(15,mono=True),fill=accent)
    for j, note in enumerate(NOTES[stage]):
        d.text((792,464+j*41),note,font=font(20),fill=WHITE)
    d.line((48,656,1232,656),fill=LINE,width=2)
    d.line((48,656,48+int(1184*t/SECONDS),656),fill=accent,width=3)
    d.text((48,679),'Configuration signal ≠ proven exploitation',font=font(17),fill=MUTED)
    d.text((909,679),'ILLUSTRATIVE / NOT LIVE OUTPUT',font=font(15,mono=True),fill=MUTED)
    return im

def main():
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        raise SystemExit('ffmpeg is required')
    command = [ffmpeg,'-y','-hide_banner','-loglevel','error','-f','rawvideo','-pixel_format','rgb24','-video_size',f'{W}x{H}','-framerate',str(FPS),'-i','-','-an','-c:v','libx264','-preset','medium','-crf','21','-pix_fmt','yuv420p','-movflags','+faststart',str(OUT/'cli-workflow.mp4')]
    process = subprocess.Popen(command,stdin=subprocess.PIPE)
    try:
        for i in range(FPS*SECONDS):
            rendered = frame(i/FPS)
            if i == 36:
                rendered.save(OUT/'cli-workflow-poster.jpg',quality=92)
            process.stdin.write(rendered.tobytes())
        process.stdin.close()
        if process.wait() != 0:
            raise SystemExit('Video encoding failed')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    print(f'Rendered {SECONDS}s / {W}x{H} / {FPS}fps: {OUT / "cli-workflow.mp4"}')

if __name__ == '__main__':
    main()
