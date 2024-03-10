use std::{fmt::Display, time::Duration};

use chrono::Local;
use eframe::App;
use egui::{vec2, Sense};
use egui_extras::{Column, TableBuilder};
use task_manager::{
    display_error_message, fetch_proc_name, filetime_to_systemtime, get_process_list,
    terminate_process, ProcessAttributes,
};

#[derive(Clone, Debug, PartialEq)]
enum SortProcesses {
    Name(String),
    CpuUsage,
    RamUsage,
    DriveUsage,
    Pid,
}

impl Display for SortProcesses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            &format!("{}", match self {
                SortProcesses::Name(_) => "Name",
                SortProcesses::CpuUsage => "CPU usage",
                SortProcesses::RamUsage => "RAM usage",
                SortProcesses::DriveUsage => "Drive usage",
                SortProcesses::Pid => "Process ID",
            })
        )
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
enum Unit {
    B,
    KB,
    MB,
    GB,
    TB,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct TaskManager {
    #[serde(skip)]
    current_process_list: Vec<ProcessAttributes>,

    #[serde(skip)]
    last_process_list: Vec<ProcessAttributes>,

    #[serde(skip)]
    last_check_time: chrono::DateTime<Local>,

    #[serde(skip)]
    last_check: std::time::Instant,

    update_frequency: u64,

    processor_usage: f64,

    biggest_col_height: f32,

    #[serde(skip)]
    sort_processes: Option<SortProcesses>,

    memory_unit: Unit,
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
            last_process_list: Vec::new(),

            last_check_time: chrono::Local::now(),
            last_check: std::time::Instant::now(),
            update_frequency: 3,

            biggest_col_height: 400.,

            processor_usage: 0.,

            sort_processes: None,
            memory_unit: Unit::MB,
        }
    }
}

impl App for TaskManager {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.menu_button("Settings", |ui| {
                    ui.label("Process check delay (Seconds)");
                    ui.add(egui::widgets::Slider::new(
                        &mut self.update_frequency,
                        1..=30,
                    ));

                    ui.horizontal(|ui| {
                        ui.label("Memory unit");

                        let combobox = egui::ComboBox::from_id_source("Memory unit")
                            .selected_text(format!("{:?}", self.memory_unit) )
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.memory_unit, Unit::B, "B");
                                ui.selectable_value(&mut self.memory_unit, Unit::KB, "KB");
                                ui.selectable_value(&mut self.memory_unit, Unit::MB, "MB");
                                ui.selectable_value(&mut self.memory_unit, Unit::GB, "GB");
                                ui.selectable_value(&mut self.memory_unit, Unit::TB, "TB");
                            });

                        ui.allocate_space(vec2(0., 120.));
                    });
                });

                ui.menu_button("Search", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Search parameters");

                        egui::ComboBox::from_id_source("Search")
                            .selected_text({
                                if let Some(search_parameter) = &self.sort_processes {
                                    format!("{}", search_parameter)
                                } else {
                                    format!("{:?}", None::<()>)
                                }
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.sort_processes,
                                    Some(SortProcesses::CpuUsage),
                                    "CPU Usage",
                                );
                                ui.selectable_value(
                                    &mut self.sort_processes,
                                    Some(SortProcesses::Name(String::new())),
                                    "Name",
                                );
                                ui.selectable_value(
                                    &mut self.sort_processes,
                                    Some(SortProcesses::RamUsage),
                                    "RAM Usage",
                                );
                                ui.selectable_value(
                                    &mut self.sort_processes,
                                    Some(SortProcesses::DriveUsage),
                                    "Drive usage",
                                );
                                ui.selectable_value(
                                    &mut self.sort_processes,
                                    Some(SortProcesses::Pid),
                                    "Process ID",
                                );
                            });

                        ui.allocate_space(vec2(0., 120.));

                    });

                    if let Some(SortProcesses::Name(inner_string)) = self.sort_processes.as_mut() {
                        ui.text_edit_singleline(inner_string);
                    }

                });

                ui.label(format!(
                    "Process count: {} | Processor usage: {}%",
                    self.current_process_list.len(),
                    self.processor_usage
                ));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            TableBuilder::new(ui)
                .resizable(true)
                .striped(true)
                .columns(
                    Column::auto_with_initial_suggestion(ctx.available_rect().width() / 5.),
                    5,
                )
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
                    });
                })
                .body(|mut body| {
                    //Insert process flags here
                    for (index, proc_attributes) in self.current_process_list.iter().enumerate() {
                        body.row(25., |mut row| {
                            //proc_name
                            let proc_name = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(fetch_proc_name(proc_attributes.process.szExeFile))
                                });
                            });

                            if proc_name.0.height() > self.biggest_col_height {
                                self.biggest_col_height = proc_name.0.height()
                            };

                            //processor usage DONT TOUCH
                            let proc_usage = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    //(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 1) as f64
                                    if let Some(last_proc_list) = self.last_process_list.get(index)
                                    {
                                        //Check if this process is exiting (wtf MS), for some unkown reason last_proc is bigger when terminating / exiting, therefor causes a crash
                                        if (proc_attributes.process_cpu_info.cpu_time_kernel
                                            + proc_attributes.process_cpu_info.cpu_time_user)
                                            >= (last_proc_list.process_cpu_info.cpu_time_kernel
                                                + last_proc_list.process_cpu_info.cpu_time_user)
                                        {
                                            let usage = (proc_attributes
                                                .process_cpu_info
                                                .cpu_time_kernel
                                                + proc_attributes.process_cpu_info.cpu_time_user
                                                - last_proc_list.process_cpu_info.cpu_time_kernel
                                                + last_proc_list.process_cpu_info.cpu_time_user)
                                                .as_secs_f64()
                                                / (chrono::Local::now().timestamp() as f64
                                                    / self.last_check_time.timestamp() as f64);

                                            /*(cur_time / prev_time) */
                                            ui.label(format!("{:.2} %", usage));
                                        }
                                    }

                                    // filetime_to_systemtime(proc_attributes.process_cpu_info);
                                });
                            });

                            //thread count
                            let thread_count = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.process.cntThreads))
                                });
                            });

                            //ram usage
                            let ram_usage = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    //In bytes
                                    let memory_usage =
                                        proc_attributes.process_memory.WorkingSetSize;

                                    ui.label(match self.memory_unit {
                                        Unit::B => format!("{} B", memory_usage),
                                        Unit::KB => format!("{:.1} KB", memory_usage / 1024),
                                        Unit::MB => {
                                            format!("{:.2} MB", memory_usage as f32 / 1024_f32.powf(2.))
                                        }
                                        Unit::GB => {
                                            format!("{:.3} GB", memory_usage as f32 / 1024_f32.powf(3.))
                                        }
                                        Unit::TB => {
                                            format!("{:.5} TB", memory_usage as f32 / 1024_f32.powf(4.))
                                        }
                                    });
                                });
                            });

                            //process id
                            let proc_id = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.process.th32ProcessID))
                                });
                            });

                            if proc_id.1.clicked() {
                                ctx.copy_text(proc_attributes.process.th32ProcessID.to_string());
                            }

                            proc_name.1.context_menu(|ui| {
                                ui.label("Process settings");

                                ui.separator();

                                if ui.button("Terminate process").clicked() {
                                    if let Err(err) =
                                        terminate_process(proc_attributes.process.th32ProcessID)
                                    {
                                        display_error_message(err, "Error");
                                    };
                                }

                                if ui.button("Terminate parent process").clicked() {
                                    if let Err(err) = terminate_process(
                                        proc_attributes.process.th32ParentProcessID,
                                    ) {
                                        display_error_message(err, "Error");
                                    };
                                }

                                ui.separator();
                            });

                            proc_id.1.on_hover_text_at_pointer("Left click top copy");

                            proc_name
                                .1
                                .on_hover_text_at_pointer("Right click for more options");

                            //returns response
                            if row.response().interact(Sense::click()).clicked() {
                                println!("Fasz!");
                            }
                        });
                    }
                });
        });

        //Check for processes
        if self.last_check.elapsed() > Duration::from_secs(self.update_frequency) {
            self.last_check = std::time::Instant::now();

            self.last_check_time = chrono::Local::now();

            self.processor_usage = 0.;

            //Run the proc finding
            match get_process_list() {
                Ok(proc_list) => {
                    if self.current_process_list.is_empty() {
                        self.last_process_list = proc_list.clone();
                    } else {
                        self.last_process_list = self.current_process_list.clone();
                    }

                    self.current_process_list = proc_list;
                }
                Err(err) => {
                    dbg!(err.backtrace());
                    display_error_message(format!("{err}"), "Error");
                }
            }
        }

        //run 4 ever
        ctx.request_repaint();
    }
    
    //Persistence
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }
}
