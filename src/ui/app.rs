use std::time::Duration;

use eframe::App;
use egui::Sense;
use egui_extras::{Column, TableBuilder};
use task_manager::{
    display_error_message, fetch_proc_name, get_memory_usage, get_process_list, get_self_proc_id,
};
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;

#[derive(Clone, Debug, PartialEq)]
enum SortProcesses {
    Name(String),
    CpuUsage,
    RamUsage,
    DriveUsage,
    Pid,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct TaskManager {
    #[serde(skip)]
    current_process_list: Vec<PROCESSENTRY32W>,

    #[serde(skip)]
    last_check: std::time::Instant,
    update_frequency: u64,

    biggest_col_height: f32,

    #[serde(skip)]
    sort_processes: Option<SortProcesses>,
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
        Self {
            current_process_list: Vec::new(),
            last_check: std::time::Instant::now(),
            update_frequency: 3,

            biggest_col_height: 400.,

            sort_processes: None,
        }
    }
}

impl App for TaskManager {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.menu_button("Settings", |ui| {
                    ui.label("Process check delay (Seconds)");
                    ui.add(egui::widgets::Slider::new(
                        &mut self.update_frequency,
                        1..=30,
                    ));
                });

                ui.menu_button("Search", |ui| {

                    if let Some(SortProcesses::Name(inner_string)) = self.sort_processes.as_mut() {
                        ui.text_edit_singleline(inner_string);
                    }

                    egui::ComboBox::from_id_source("Search")
                        .selected_text({
                            if let Some(search_parameter) = &self.sort_processes {
                                format!("{:?}", search_parameter)
                            }
                            else {
                                format!("{:?}", self.sort_processes.clone())
                            }
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::CpuUsage),
                                "Cpu Usage",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::Name(String::new())),
                                "Name",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::RamUsage),
                                "Ram Usage",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::DriveUsage),
                                "Drive usage",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::Pid),
                                "Process Id",
                            );
                        });
                });
                
                ui.label(format!("Process count: {}", self.current_process_list.len()));

            });

        });

        egui::CentralPanel::default().show(ctx, |ui| {
            TableBuilder::new(ui)
                .resizable(true)
                .striped(true)
                .columns(Column::auto_with_initial_suggestion(ctx.available_rect().width() / 5.), 5)
                .header(25., |mut row| {
                    //Main rows (ram usage, etc)
                    row.col(|ui| {
                        ui.label("Process name");
                    });
                    row.col(|ui| {
                        ui.label("Processor usage");
                    });
                    row.col(|ui| {
                        ui.label("Thread count");
                    });
                    row.col(|ui| {
                        ui.label("Ram usage");
                    });
                    row.col(|ui| {
                        ui.label("Process ID");

                        // //Fill out the rest of the ui
                        // ui.allocate_space(ui.available_size());
                    });
                })
                .body(|mut body| {
                    //Insert process flags here
                    for proc_attributes in &self.current_process_list {
                        body.row(25., |mut row| {
                            //proc_name
                            let col_height = row
                                .col(|ui| {
                                    ui.horizontal_centered(|ui| {
                                        ui.label(fetch_proc_name(proc_attributes.szExeFile))
                                    });
                                })
                                .0
                                .height();

                            if col_height > self.biggest_col_height {
                                self.biggest_col_height = col_height
                            };

                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.cntUsage))
                                });
                            });
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.cntThreads))
                                });
                            });
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    match get_memory_usage(proc_attributes.th32ProcessID) {
                                        Ok(memory) => {
                                            ui.label(format!("{memory} B"));
                                        }
                                        Err(err) => {
                                            //We dont want to make a prompt because then there isnt only one occuerence of tis errors
                                            ui.label(format!("{err}"));
                                        }
                                    }
                                });
                            });
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.th32ProcessID))
                                });
                            });

                            //returns response
                            if row.response().interact(Sense::click()).clicked() {
                                println!("asd {}", row.col_index());
                            }

                        });
                    }
                });
        });

        //Check for processes
        if self.last_check.elapsed() >= Duration::from_secs(self.update_frequency) {
            self.last_check = std::time::Instant::now();

            //Run the proc finding
            match get_process_list() {
                Ok(proc_list) => {
                    self.current_process_list = proc_list;
                }
                Err(err) => {
                    display_error_message(format!("{err}"), "Error");
                }
            }
        }

        //run 4 ever
        ctx.request_repaint();
    }
}
