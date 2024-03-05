#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::NativeOptions;

pub mod ui;

fn main() -> anyhow::Result<(), Box<dyn std::error::Error>> {
    eframe::run_native(
        "Task Manager",
        {
            NativeOptions {
                ..Default::default()
            }
        },
        Box::new(|cc| Box::new(ui::app::TaskManager::new(cc))),
    )?;

    Ok(())
}
