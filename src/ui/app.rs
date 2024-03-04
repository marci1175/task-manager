use eframe::App;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct TaskManager {

}

impl TaskManager {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        if let Some(storage) = cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
    }
}

impl Default for TaskManager {
    fn default() -> Self {
        Self {  }
    }
}

impl App for TaskManager {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            
        });
    }
}