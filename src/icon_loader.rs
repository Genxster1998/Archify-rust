#[cfg(target_os = "macos")]
pub fn get_app_icon_rgba(app_path: &std::path::Path, target_size: u32) -> Option<(u32, u32, Vec<u8>)> {
    use objc2_app_kit::{NSWorkspace, NSBitmapImageRep, NSBitmapImageFileType};
    use objc2_foundation::{NSString, NSDictionary, NSRect, NSPoint, NSSize};
    use objc2::rc::{autoreleasepool, Retained};
    use objc2::{AnyThread, msg_send};
    
    let path_str = app_path.to_str()?;
    let path = NSString::from_str(path_str);
    
    autoreleasepool(|_| unsafe {
        let workspace = NSWorkspace::sharedWorkspace();
        let image = workspace.iconForFile(&path);
        
        // Request a CGImage for the proposed target size directly!
        // This makes Cocoa select the pre-rendered 64x64 or 128x128 representation,
        // avoiding the massive 70MB TIFF serialization of all resolutions.
        let mut rect = NSRect {
            origin: NSPoint { x: 0.0, y: 0.0 },
            size: NSSize { width: target_size as f64, height: target_size as f64 },
        };
        
        // Retained<objc2_core_graphics::CGImage> has the expected '^{CGImage=}' type code
        let cg_image: Option<Retained<objc2_core_graphics::CGImage>> = msg_send![
            &image,
            CGImageForProposedRect: &mut rect,
            context: Option::<&objc2_app_kit::NSGraphicsContext>::None,
            hints: Option::<&NSDictionary>::None,
        ];
        
        let cg_image = cg_image?;
        
        let bitmap: Option<Retained<NSBitmapImageRep>> = msg_send![
            NSBitmapImageRep::alloc(),
            initWithCGImage: &*cg_image
        ];
        let bitmap = bitmap?;
        
        let properties = NSDictionary::new();
        let png_data = bitmap.representationUsingType_properties(
            NSBitmapImageFileType::PNG,
            &properties
        )?;
        
        let bytes = png_data.to_vec();
        let img = image::load_from_memory(&bytes).ok()?;
        
        // Resize to target size (Triangle filter is super fast)
        let resized = img.resize(target_size, target_size, image::imageops::FilterType::Triangle);
        let rgba = resized.to_rgba8();
        
        Some((target_size, target_size, rgba.into_raw()))
    })
}

#[cfg(not(target_os = "macos"))]
pub fn get_app_icon_rgba(_app_path: &std::path::Path, _target_size: u32) -> Option<(u32, u32, Vec<u8>)> {
    None
}
