import "pe"
import "hash"


rule ryk_Ransomware {
    meta:
        description = "Detects svchost.exe ransomware payload"
        author = "LWH" 
        date = "2025-08-25"
        threat_name = "svchost_Ransomware"
        category = "Ransomware"
        
    strings:
        // Ransomware behavior
        $ransom_ext = ".ryk" ascii wide
        $ransom_note = "readme.txt" ascii wide
        $recover_key = "Recover Key:" ascii wide
        
        // File extension targets
        $ext1 = ".xlsx" ascii wide nocase
        $ext2 = ".docx" ascii wide nocase
        $ext3 = ".pdf" ascii wide nocase
        $ext4 = ".jpg" ascii wide nocase
        $ext5 = ".png" ascii wide nocase
        $ext6 = ".mp4" ascii wide nocase
        $ext7 = ".zip" ascii wide nocase
        $ext8 = ".hwp" ascii wide nocase
        
        // Crypto operations (Go AES GCM)
        $crypto1 = "crypto/aes" ascii
        $crypto2 = "crypto/cipher" ascii
        $crypto3 = "crypto/rand" ascii
        $gcm_mode = "NewGCM" ascii
        $aes_key = "NewCipher" ascii
        
        // Virtual machine detection
        $vm_check1 = "00:05:69" ascii // VMware
        $vm_check2 = "00:0c:29" ascii // VMware
        $vm_check3 = "08:00:27" ascii // VirtualBox
        $vm_check4 = "vmware" ascii nocase
        $vm_check5 = "virtualbox" ascii nocase
        $vm_check6 = "vethernet" ascii nocase
        $vm_check7 = "vmnet" ascii nocase
        
        // ryk message
        $ryk_title = "ABCCompnay" ascii wide
        $ryk_msg = "job seeker" ascii wide nocase
        
        // Wallpaper change
        $wallpaper1 = "w.png" ascii wide
        $wallpaper2 = "setwallpaper" ascii nocase
        
        // Go binary markers
        $go_main = "main.main" ascii
        $go_slice = "runtime.makeslice" ascii
//        $go_ReadAtLeast = "io.ReadAtLeast." ascii
        
    condition:
        // PE file validation and section check
        pe.is_pe and
        pe.number_of_sections > 4 and
        (for any section in pe.sections : (section.name == "/4"))  and
        (for any section in pe.sections : (section.name == "/19")) and
        (for any section in pe.sections : (section.name == "/32")) and

        
        // File size typical for Go ransomware
        filesize > 2MB and filesize < 15MB and
        
        // Ransomware core functionality
        $ransom_ext and ($ransom_note or $recover_key) and
        
        // Crypto operations
        2 of ($crypto*) and ($gcm_mode or $aes_key) and
        
        // File extension targeting
        4 of ($ext*) and
        
        // Anti-analysis (VM detection)
        2 of ($vm_check*) or
        
        // Go language indicators
        any of ($go_*) and
        
        // Known characteristics
        (($ryk_title and $ryk_msg) or 
         any of ($wallpaper*) or
         hash.sha256(0, filesize) == "6be9168223ea35f0da9a940230dfd3ea35f49c7b86ede306870fe898bacceb52")
}