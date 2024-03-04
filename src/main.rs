use eframe::NativeOptions;

mod ui;

fn main() -> anyhow::Result<(), Box<dyn std::error::Error>> {
    eframe::run_native("Task Manager", {
        NativeOptions {
            ..Default::default()
        }
    }, Box::new(|cc| Box::new(ui::app::TaskManager::new(cc))))?;

    Ok(())
}
